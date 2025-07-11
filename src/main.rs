use clap::{Parser, Subcommand};
use git2::{Repository, RepositoryInitOptions, RepositoryOpenFlags};
use pathdiff::diff_paths;
use regex::Regex;
use trie_rs::inc_search::{Answer, IncSearch};
use trie_rs::TrieBuilder;

use std::env::current_dir;
use std::fs::{self, File};
use std::hint::unreachable_unchecked;
use std::io::{self, BufRead};
#[cfg(not(unix))]
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{absolute, Component, Path, PathBuf};
use std::str::FromStr;
mod glob_to_regex;
use glob_to_regex::glob_to_regex;

#[derive(Parser, Debug)]
#[command(name = "git-overlay")]
#[command(
    version,
    about = "Version control for gitignored files by overlaying a separate repository"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new overlay repository in the current git repo
    Init {
        /// Remote URL for the overlay repository
        #[arg(short, long)]
        remote: Option<String>,
    },
    /// Clone and import an existing overlay repository
    Import {
        /// URL of the overlay repository to import
        url: String,
        /// Optional path to clone into (defaults to .git/overlay)
        path: Option<PathBuf>,
    },
    /// Add files to the overlay repository
    Add {
        /// Files or directories to add to overlay
        paths: Vec<PathBuf>,
    },
    /// Commit changes to overlay repository
    CommitHook {},
    /// Checkout and synchronize overlay files
    PostCheckoutHook {
        target: String,
        prev: String,
        // branch: bool
    },
    /// Push overlay repositories
    Push {
        /// Remote name (defaults to origin)
        #[arg(short, long, default_value = "origin")]
        remote: String,
    },
    /// Fetch and synchronize overlay repository
    Fetch {
        /// Remote name (defaults to origin)
        #[arg(short, long, default_value = "origin")]
        remote: String,
    },
    /// Show status of both base and overlay repositories
    Status,
    LsFiles {
        paths: Vec<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { remote } => init_overlay(remote),
        Commands::Import { url, path } => import_overlay(url, path),
        Commands::Add { paths } => add_to_overlay(paths),
        Commands::CommitHook {} => commit_hook(),
        Commands::PostCheckoutHook { target, prev } => {
            post_checkout_hook(&target, &prev, true).unwrap();
        }
        Commands::Push { remote } => push_overlay(remote),
        Commands::Fetch { remote } => fetch_overlay(remote),
        Commands::Status => show_status(),
        Commands::LsFiles { paths } => ls_files_overlay(paths),
    }
}

fn add_to_overlay(paths: Vec<PathBuf>) {
    let overlay = GitOverlay::open(".").unwrap();

    overlay.add_to_overlay(paths).unwrap();
}

fn init_overlay(remote: Option<String>) {
    match init_overlay_impl(remote) {
        Ok(_) => println!("Successfully initialized overlay repository"),
        Err(e) => {
            eprintln!("Error initializing overlay repository: {}", e);
            std::process::exit(1);
        }
    }
}

fn init_overlay_impl(remote: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're in a git repository
    let base_repo = Repository::open(".")?;
    let git_dir = base_repo.path();

    // Create overlay directory path
    let overlay_path = git_dir.join("overlay");

    // Check if overlay already exists
    if overlay_path.exists() {
        return Err(
            "Overlay repository already exists. Use 'git-overlay status' to check its state."
                .into(),
        );
    }

    println!("Initializing overlay repository in {:?}...", overlay_path);

    // Create the overlay directory
    fs::create_dir_all(&overlay_path)?;

    // Initialize the overlay repository
    let mut init_opts = RepositoryInitOptions::new();
    init_opts.bare(true);
    let overlay_repo = Repository::init_opts(&overlay_path, &init_opts)?;

    // Set up remote if provided
    if let Some(url) = remote {
        println!("Adding remote 'origin' with URL: {}", url);
        overlay_repo.remote("origin", &url)?;
    }

    Ok(())
}

fn import_overlay(url: String, path: Option<PathBuf>) {
    println!("Cloning overlay repository from: {}", url);
    if let Some(p) = path {
        println!("Into path: {:?}", p);
    }
    // TODO: Clone overlay repo and set up in .git/overlay
}
}

}

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

fn regexes_from_pattern_file(path: PathBuf, prefix: &str) -> Vec<(Regex, bool, bool)> {
    let mut regexes = Vec::new();

    if let Ok(lines) = read_lines(path) {
        let glob_patterns = parse_pattern_file(lines);
        // for (pat, negate) in &glob_patterns {
        //     println!("  {} {}", pat, negate);
        // }
        for (glob_pattern, negate) in glob_patterns {
            if let Some((regex, only_files)) = glob_to_regex(&glob_pattern, &prefix) {
                // println!("  regex: {}", regex.as_str());
                regexes.push((regex, negate, only_files));
            }
        }
    }

    return regexes;
}

fn join_regex_slices<'a>(
    base: &[&'a (Regex, bool, bool)],
    additional: &'a [(Regex, bool, bool)],
) -> Vec<&'a (Regex, bool, bool)> {
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

fn path_matches(path: &str, patterns: &[&(Regex, bool, bool)], is_dir: bool) -> bool {
    let mut matches = false;
    for (regex, negate, only_files) in patterns {
        if matches != *negate {
            continue;
        }
        if is_dir && *only_files {
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

struct GitOverlay {
    base_repo: Repository,
    overlay_repo: Repository,
}

// #[subenum(OpenError)]
#[derive(Debug)]
enum GitOverlayError {
    Git2Error(git2::Error),
    IoError(io::Error),
    /// Base Repository is bare
    BareBase,
    /// Overlay Repository is bare
    BareOverlay,
    /// Overlay already exists
    OverlayExists,
    /// Path is outside both the base and the overlay repository
    PathOutsideRepos,
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
struct GitPathRef<'a> {
    buf: &'a [u8],
}

#[cfg(not(unix))]
struct GitPathRef<'a> {
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
fn git_style_path_to_path(path: GitPathRef) -> PathBuf {
    // todo
}

#[cfg(not(unix))]
fn path_to_git_style_path(path: &Path) -> GitPathRef {
    // todo
}

#[cfg(unix)]
fn git_style_path_to_path(path: GitPathRef) -> PathBuf {
    Path::new(std::ffi::OsStr::from_bytes(path.to_bytes())).to_path_buf()
}

#[cfg(unix)]
fn path_to_git_style_path(path: &Path) -> GitPathRef {
    GitPathRef::from(path.as_os_str().as_bytes())
}

impl GitOverlay {
    fn open<P: AsRef<Path>>(base_repo: P) -> Result<GitOverlay, GitOverlayError> {
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
    fn import(base_repo: &PathBuf, remote_url: &str) {}

    /// Get the path to the root directory of the base repository
    fn base_root(&self) -> &Path {
        return match self.base_repo.workdir() {
            Some(path) => path,
            None => unsafe { unreachable_unchecked() },
        };
    }

    fn normal_git_path(&self, path: &Path) -> Result<Vec<u8>, GitOverlayError> {
        let path = normalize_path(absolute(path)?.as_path());
        let relative_path = if path.starts_with(self.base_root()) {
            diff_paths(path, self.base_root())
        } else {
            return Err(GitOverlayError::PathOutsideRepos);
        };
        let relative_path = match relative_path {
            Some(path) => path,
            None => unsafe { unreachable_unchecked() },
        };

        let git_path = path_to_git_style_path(relative_path.as_path()).to_owned();
        // let mut git_path = vec![b'/'];
        // git_path.extend_from_slice(path_to_git_style_path(relative_path.as_path()).into());

        return Ok(git_path);
    }

    fn get_matching_files(
        &self,
        dir: &Path,
        git_path: GitPathRef,
        patterns_ignore: Option<&[&(Regex, bool, bool)]>,
        patterns_overlay: &[&(Regex, bool, bool)],
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

        let mut all_patterns_ignore: Option<&[&(Regex, bool, bool)]> = None;
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

    fn add_to_overlay(&self, paths: Vec<PathBuf>) -> Result<(), GitOverlayError> {
        println!("Adding paths to overlay: {:?}", paths);
        // TODO: Check .overlayignore patterns, copy files to overlay, stage them
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

            add_to_index(&mut index, GitPathRef::from(git_path.as_slice()), file);
        }
        index.write()?;
        Ok(())
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

fn commit_hook() {
    println!("Committing with");
    let overlay = GitOverlay::open(".").unwrap();
    let base_hash = overlay
        .base_repo
        .head()
        .unwrap()
        .resolve()
        .unwrap()
        .target()
        .unwrap();
    let signature = overlay.overlay_repo.signature().unwrap();
    let tree_oid = overlay.overlay_repo.index().unwrap().write_tree().unwrap();
    let tree = overlay.overlay_repo.find_tree(tree_oid).unwrap();
    let parent = overlay
        .overlay_repo
        .head()
        .unwrap()
        .peel_to_commit()
        .unwrap();

    let oid = overlay
        .overlay_repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            &base_hash.to_string(),
            &tree,
            &[&parent],
        )
        .unwrap();

    let _ = overlay.overlay_repo.tag(
        &base_hash.to_string(),
        overlay.overlay_repo.find_commit(oid).unwrap().as_object(),
        &signature,
        &base_hash.to_string(),
        true,
    );
}

fn post_checkout_hook(target: &str, prev: &str, branch: bool) -> Result<(), GitOverlayError> {
    let overlay = GitOverlay::open(".").unwrap();

    // Find the overlay commit associated with the target base commit
    let tag_name = format!("refs/tags/{}", target);
    let reference = overlay.overlay_repo.find_reference(&tag_name)?;
    let object = reference.peel(git2::ObjectType::Commit)?;
    let commit = object
        .into_commit()
        .map_err(|_| git2::Error::from_str("Not a commit"))?;

    // walk the commit's tree and write the trees files into the base repo

    Ok(())
}

fn push_overlay(remote: String) {
    println!("Pushing to remote: {}", remote);
    // TODO: Push base repo, then push overlay repo
}

fn fetch_overlay(remote: String) {
    println!("Pulling from remote: {}", remote);
    // TODO: Pull base repo, then pull and sync overlay repo
}

fn show_status() {
    println!("Status of base and overlay repositories:");
    // TODO: Show git status for both base and overlay repos
}
