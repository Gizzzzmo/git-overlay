use git2::{Repository, RepositoryOpenFlags};
use pathdiff::diff_paths;
use regex::Regex;
use trie_rs::inc_search::{Answer, IncSearch};
use trie_rs::TrieBuilder;

use std::env::current_dir;
use std::fs::File;
use std::hint::unreachable_unchecked;
use std::io::{self, BufRead};
#[cfg(not(unix))]
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{absolute, Component, Path, PathBuf};
use std::str::FromStr;

mod glob_to_regex;
use glob_to_regex::{glob_to_regex, MatchTarget};

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn parse_pattern_file(input: io::Lines<io::BufReader<File>>) -> Vec<(String, bool)> {
    let mut result = Vec::new();
    for line in input {
        let Ok(line) = line else {
            continue; // ignore badly encoded lines
        };
        let Some(first) = line.chars().next() else {
            continue; // ignore empty lines
        };
        if first == '#' {
            continue; // ignore comment lines
        }
        let negate = first == '!';
        let trimmed = line.trim_ascii_end();
        if negate && trimmed.len() == 1 {
            continue; // ignore lines that only contain exactly an exclamation point (modulo
                      // trailing whitespace)
        }
        if trimmed.len() == line.len() {
            if negate {
                result.push((String::from_str(&line[1..]).unwrap(), true));
            } else {
                result.push((line, false));
            }
            continue;
        }
        let last = match trimmed.chars().last() {
            Some(c) => c,
            None => first,
        };
        let begin = if negate { 1 } else { 0 };
        // add back one trailing whitespace (ascii whitespace is 1 byte large) if it was escaped
        let end = if last == '\\' {
            trimmed.len() + 1
        } else {
            trimmed.len()
        };
        result.push((String::from_str(&line[begin..end]).unwrap(), negate));
    }

    return result;
}

fn regexes_from_pattern_file(path: PathBuf, prefix: &str) -> Vec<(Regex, bool, MatchTarget)> {
    let mut regexes = Vec::new();

    if let Ok(lines) = read_lines(path) {
        let glob_patterns = parse_pattern_file(lines);
        // for (pat, negate) in &glob_patterns {
        //     println!("  {} {}", pat, negate);
        // }
        for (glob_pattern, negate) in glob_patterns {
            if let Some((regex, match_target)) = glob_to_regex(&glob_pattern, &prefix) {
                // println!("  regex: {}", regex.as_str());
                regexes.push((regex, negate, match_target));
            }
        }
    }

    return regexes;
}

fn join_regex_slices<'a>(
    base: &[&'a (Regex, bool, MatchTarget)],
    additional: &'a [(Regex, bool, MatchTarget)],
) -> Vec<&'a (Regex, bool, MatchTarget)> {
    let mut combined = Vec::new();
    if additional.len() > 0 {
        for pat in base {
            combined.push(*pat);
        }
        for new_pat in additional {
            combined.push(&new_pat);
        }
    }
    return combined;
}

fn path_matches(path: &str, patterns: &[&(Regex, bool, MatchTarget)], is_dir: bool) -> bool {
    let mut matches = false;
    for (regex, negate, match_target) in patterns {
        if matches != *negate {
            continue;
        }
        // Skip pattern if it doesn't match the current path type
        if *match_target == MatchTarget::OnlyFiles && is_dir {
            continue;
        }
        if *match_target == MatchTarget::OnlyDirs && !is_dir {
            continue;
        }
        if regex.is_match(path) {
            matches = !matches;
        }
    }

    return matches;
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

pub struct GitOverlay {
    pub base_repo: Repository,
    pub overlay_repo: Repository,
}

// #[subenum(OpenError)]
#[derive(Debug)]
pub enum GitOverlayError {
    Git2Error(git2::Error),
    IoError(io::Error),
    /// Base Repository is bare
    BareBase,
    /// Overlay already exists
    OverlayExists,
    /// Path is outside the repository
    PathOutsideRepo,
}

impl From<io::Error> for GitOverlayError {
    fn from(value: io::Error) -> Self {
        GitOverlayError::IoError(value)
    }
}

impl From<git2::Error> for GitOverlayError {
    fn from(value: git2::Error) -> Self {
        GitOverlayError::Git2Error(value)
    }
}

#[cfg(unix)]
pub struct GitPathRef<'a> {
    buf: &'a [u8],
}

#[cfg(not(unix))]
pub struct GitPathRef<'a> {
    buf: Vec<u8>,
    ph: PhantomData<&'a [u8]>,
}

impl<'a> From<&'a [u8]> for GitPathRef<'a> {
    #[cfg(unix)]
    fn from(value: &'a [u8]) -> Self {
        GitPathRef { buf: value }
    }
    #[cfg(not(unix))]
    fn from(value: &'a [u8]) -> Self {
        GitPathRef {
            buf: value.iter().map(|b| *b).collect::<Vec<u8>>(),
            ph: PhantomData,
        }
    }
}

impl<'a> GitPathRef<'a> {
    #[cfg(unix)]
    fn to_owned(self) -> Vec<u8> {
        self.buf.iter().map(|b| *b).collect()
    }
    #[cfg(unix)]
    fn to_bytes(&self) -> &[u8] {
        self.buf
    }
    #[cfg(not(unix))]
    fn to_owned(self) -> Vec<u8> {
        self.buf
    }
    #[cfg(not(unix))]
    fn to_bytes(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(not(unix))]
pub fn git_style_path_to_path(path: GitPathRef) -> PathBuf {
    // todo
}

#[cfg(not(unix))]
pub fn path_to_git_style_path(path: &Path) -> GitPathRef {
    // todo
}

#[cfg(unix)]
pub fn git_style_path_to_path(path: GitPathRef) -> PathBuf {
    Path::new(std::ffi::OsStr::from_bytes(path.to_bytes())).to_path_buf()
}

#[cfg(unix)]
pub fn path_to_git_style_path(path: &Path) -> GitPathRef {
    GitPathRef::from(path.as_os_str().as_bytes())
}

impl GitOverlay {
    pub fn init<P: AsRef<Path>>(
        base_repo: P,
        remote_url_and_pull: Option<(&str, bool)>,
    ) -> Result<GitOverlay, GitOverlayError> {
        let base_repo = Repository::open_ext(
            base_repo,
            RepositoryOpenFlags::CROSS_FS,
            &[] as &[&std::ffi::OsStr],
        )?;
        let overlay_path = base_repo.path().join("overlay");
        if base_repo.is_bare() {
            return Err(GitOverlayError::BareBase);
        }

        let Err(_) = Repository::open(&overlay_path) else {
            return Err(GitOverlayError::OverlayExists);
        };

        std::fs::create_dir_all(&overlay_path)?;

        let overlay = GitOverlay {
            base_repo,
            overlay_repo: Repository::init_bare(overlay_path)?,
        };

        let Some((remote_url, pull)) = remote_url_and_pull else {
            return Ok(overlay);
        };

        let mut remote = overlay.overlay_repo.remote("origin", remote_url)?;
        if pull {
            remote.fetch(&[] as &[&str], None, None)?;
            // overlay.post_checkout_hook();
        }
        drop(remote);
        return Ok(overlay);
    }

    pub fn open<P: AsRef<Path>>(base_repo: P) -> Result<GitOverlay, GitOverlayError> {
        let base_repo = Repository::open_ext(
            base_repo,
            RepositoryOpenFlags::CROSS_FS,
            &[] as &[&std::ffi::OsStr],
        )?;
        let overlay_path = base_repo.path().join("overlay");
        if base_repo.is_bare() {
            return Err(GitOverlayError::BareBase);
        }

        let overlay = GitOverlay {
            base_repo,
            overlay_repo: Repository::open(overlay_path)?,
        };

        return Ok(overlay);
    }

    /// Get the path to the root directory of the base repository
    pub fn base_root(&self) -> &Path {
        return match self.base_repo.workdir() {
            Some(path) => path,
            None => unsafe { unreachable_unchecked() },
        };
    }

    /// Get a normalized git-style path (relative to the root of the base repo of this overlay)
    /// to the given path.
    /// Returns GitOverlayError::PathOutsideRepo if the path does not lie under the base_repo of
    /// this overlay.
    pub fn normal_git_path(&self, path: &Path) -> Result<Vec<u8>, GitOverlayError> {
        let path = normalize_path(absolute(path)?.as_path());
        let relative_path = if path.starts_with(self.base_root()) {
            diff_paths(path, self.base_root())
        } else {
            return Err(GitOverlayError::PathOutsideRepo);
        };
        let relative_path = match relative_path {
            Some(path) => path,
            None => unsafe { unreachable_unchecked() },
        };

        let git_path = path_to_git_style_path(relative_path.as_path()).to_owned();

        return Ok(git_path);
    }

    fn get_matching_files(
        &self,
        dir: &Path,
        git_path: GitPathRef,
        patterns_ignore: Option<&[&(Regex, bool, MatchTarget)]>,
        patterns_overlay: &[&(Regex, bool, MatchTarget)],
        trie_search: &Option<IncSearch<u8, ()>>,
    ) -> Vec<(Vec<u8>, PathBuf)> {
        let git_path = std::str::from_utf8(git_path.to_bytes()).unwrap();
        // get current directory

        // println!("{}", git_path);
        let new_patterns_ignore = match patterns_ignore {
            None => Vec::new(),
            _ => regexes_from_pattern_file(dir.join(".gitignore"), git_path),
        };

        let joined = match patterns_ignore {
            None => Vec::new(),
            Some(patterns_ignore) => join_regex_slices(patterns_ignore, &new_patterns_ignore),
        };

        let mut all_patterns_ignore: Option<&[&(Regex, bool, MatchTarget)]> = None;
        if let Some(patterns_ignore) = patterns_ignore {
            if new_patterns_ignore.len() > 0 {
                all_patterns_ignore = Some(&joined);
            } else {
                all_patterns_ignore = Some(patterns_ignore);
            }
        }

        let new_patterns_overlay = regexes_from_pattern_file(dir.join(".overlayignore"), &git_path);
        let all_patterns_overlay = join_regex_slices(patterns_overlay, &new_patterns_overlay);
        let all_patterns_overlay = if new_patterns_overlay.len() > 0 {
            &all_patterns_overlay
        } else {
            patterns_overlay
        };

        let mut files = Vec::<(Vec<u8>, PathBuf)>::new();
        let Ok(dir_entries) = dir.read_dir() else {
            return files;
        };

        for dir_entry in dir_entries {
            let Ok(dir_entry) = dir_entry else {
                continue;
            };
            let next_path = dir_entry.path();
            let is_actual_dir = next_path.is_dir() && !next_path.is_symlink();
            let name = dir_entry.file_name();

            let mut add_file = true;
            let mut abort = false;

            let new_search = trie_search.to_owned().and_then(|mut new_search| {
                match new_search.query_until(name.as_bytes()) {
                    Ok(Answer::Prefix) => {
                        add_file = false;
                        _ = new_search.query_until("/");
                        Some(new_search) //
                    }
                    // if we match something no more searching is required:
                    // all descendant files / directories will be added
                    Ok(Answer::PrefixAndMatch) | Ok(Answer::Match) => None,
                    // if there is neither a prefix or a match then we are not in or underneath
                    // a directory that should be searched
                    _ => {
                        abort = true;
                        None
                    }
                }
            });

            if abort {
                continue;
            }
            if name == ".git" && is_actual_dir {
                continue; // don't descend into the .git directory
            }
            if next_path.join(".git").is_dir() {
                continue; // don't descend into nested repos
            }
            let Some(name_utf8) = name.as_os_str().to_str() else {
                continue; // git also only works with valid utf-8
            };

            let mut git_path = git_path.to_owned();
            if git_path.chars().next() != None {
                git_path.push('/');
            }
            git_path.push_str(name_utf8);

            let ignored_by_overlay = path_matches(&git_path, all_patterns_overlay, is_actual_dir);
            // println!("{}", git_path);
            // println!("  ignored by overlay: {}", ignored_by_overlay);

            if ignored_by_overlay {
                continue;
            }
            let all_patterns_ignore = all_patterns_ignore.and_then(|pats| {
                if path_matches(&git_path, pats, is_actual_dir) {
                    None
                } else {
                    Some(pats)
                }
            });

            if is_actual_dir {
                files.append(&mut self.get_matching_files(
                    next_path.as_path(),
                    git_path.as_bytes().into(),
                    all_patterns_ignore,
                    all_patterns_overlay,
                    &new_search,
                ));
            } else if matches!(all_patterns_ignore, None) && add_file {
                files.push((git_path.into_bytes(), next_path));
            }
        }

        return files;
    }

    pub fn add(&self, paths: Vec<PathBuf>) -> Result<(), GitOverlayError> {
        println!("Adding paths to overlay: {:?}", paths);
        let base_root = self.base_root();

        let mut builder = TrieBuilder::new();
        builder.push("/");
        println!("base_root: {}", base_root.to_str().unwrap());

        let mut all = false;
        for path in &paths {
            let normal_path = self.normal_git_path(path)?;
            println!("{}", std::str::from_utf8(&normal_path).unwrap());
            if normal_path.len() == 0 {
                all = true;
                break;
            }
            builder.push(normal_path);
        }
        let trie = builder.build();
        let search = if all { None } else { Some(trie.inc_search()) };

        let matching_files = self.get_matching_files(
            base_root,
            GitPathRef::from(&[] as &[u8]),
            Some(&[]),
            &[],
            &search,
        );
        println!("All files:");
        let mut index = self.overlay_repo.index()?;
        for (git_path, file) in &matching_files {
            println!(
                "{}\n{}",
                std::str::from_utf8(git_path).unwrap(),
                file.to_str().unwrap()
            );

            add_to_index(&mut index, GitPathRef::from(git_path.as_slice()), file)?;
        }
        index.write()?;
        Ok(())
    }

    pub fn ls_files(&self, mut paths: Vec<PathBuf>) -> Result<(), GitOverlayError> {
        if paths.len() == 0 {
            paths.push(PathBuf::from_str(".").unwrap());
        }
        let workdir = normalize_path(self.base_root());
        let git_dir = self.base_repo.path();
        let Ok(overlay_repo) = Repository::open(git_dir.join("overlay")) else {
            println!("Error: No overlay exists");
            return Ok(());
        };
        let cwd = current_dir().unwrap();
        let mut builder = TrieBuilder::new();

        let mut everything = false;
        for path in paths {
            let relative = diff_paths(
                normalize_path(absolute(cwd.join(path)).unwrap().as_path()),
                &workdir,
            )
            .unwrap();
            let relative = relative.to_str().unwrap();

            if relative == "" {
                everything = true;
                break;
            }
            builder.push(relative);
        }

        let trie = builder.build();
        for entry in overlay_repo.index().unwrap().iter() {
            let components_iter = entry.path.split(|b| *b == b'/');

            let mut search = trie.inc_search();
            let mut found = everything;
            for component in components_iter {
                if everything {
                    break;
                }
                // println!("check {}", std::str::from_utf8(component).unwrap());
                match search.query_until(component) {
                    Ok(Answer::Match) | Ok(Answer::PrefixAndMatch) => {
                        // println!("found {}", std::str::from_utf8(&entry.path).unwrap());
                        found = true;
                        break;
                    }
                    Ok(Answer::Prefix) => {
                        _ = search.query_until(std::path::MAIN_SEPARATOR_STR);
                    }
                    _ => break,
                }
            }

            if found {
                let relative = entry
                    .path
                    .split(|b| *b == b'/')
                    .map(|sl| std::str::from_utf8(sl).unwrap())
                    .collect::<Vec<&str>>()
                    .join(std::path::MAIN_SEPARATOR_STR);

                let abs = workdir.join(PathBuf::from_str(&relative).unwrap());

                println!("{}", diff_paths(abs, &cwd).unwrap().to_str().unwrap());
            }
        }
        return Ok(());
    }
}

fn add_to_index(
    index: &mut git2::Index,
    git_path: GitPathRef,
    file: &Path,
) -> Result<(), GitOverlayError> {
    // Read file contents into memory
    let file_contents = std::fs::read(file)?;

    let metadata = std::fs::metadata(file)?;

    #[cfg(unix)]
    let entry = {
        git2::IndexEntry {
            ctime: git2::IndexTime::new(metadata.ctime() as i32, metadata.ctime_nsec() as u32),
            mtime: git2::IndexTime::new(metadata.mtime() as i32, metadata.mtime_nsec() as u32),
            dev: metadata.dev() as u32,
            ino: metadata.ino() as u32,
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            file_size: 0,          // Will be calculated by git2
            id: git2::Oid::zero(), // Will be calculated by libgit2
            flags: 0,
            flags_extended: 0,
            path: git_path.to_owned(),
        }
    };

    // Add the file to the index using its contents
    index
        .add_frombuffer(&entry, &file_contents)
        .expect("Failed to add file to index");
    Ok(())
}
