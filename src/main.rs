use clap::{Parser, Subcommand};
use git2::{IndexEntry, Oid, Repository, RepositoryInitOptions, RepositoryOpenFlags, Signature};
use pathdiff::diff_paths;
use regex::{escape, Regex};
use subenum::subenum;
use trie_rs::inc_search::{Answer, IncSearch};
use trie_rs::TrieBuilder;

use std::env::current_dir;
use std::fs::{self, File};
use std::hint::unreachable_unchecked;
use std::io::{self, BufRead};
use std::marker::PhantomData;
use std::os::unix::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{absolute, Component, Path, PathBuf};
use std::str::{Chars, FromStr};

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
        Commands::PostCheckoutHook { target, prev, } => post_checkout_hook(&target, &prev, true),
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
    init_opts.bare(false);
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

fn glob_escape_next(it: &mut Chars, re_pattern: &mut String) -> bool {
    let view = it.as_str();
    let Some(_) = it.next() else {
        return false;
    };
    re_pattern.push_str(&escape(&view[..1]));
    return true;
}

fn glob_parse_range_end(
    mut range_start: char,
    escape_start: bool,
    mut range_end: char,
    escape_end: bool,
    re_pattern: &mut String,
) -> bool {
    if range_start > range_end {
        return false;
    }
    if range_start == '/' && range_end == '/' {
        return true;
    }

    if range_start == '/' {
        range_start = '0';
    }
    if range_end == '/' {
        range_end = '.';
    }

    if escape_start {
        re_pattern.push('\\');
    }
    re_pattern.push(range_start);
    re_pattern.push('-');

    if range_start < '/' && range_end > '/' {
        re_pattern.push_str(".0-");
    }

    if escape_end {
        re_pattern.push('\\');
    }
    re_pattern.push(range_end);

    return true;
}

/// Parses the given iterator, and pushes the corresponding regex to re_pattern, consuming all remaining
/// characters in the iterator that correspond to the glob range.
/// The character starting the range (and possibly an escaping backslash) must have been consumed by
/// the iterator at this point.
/// If the iterator is empty, or contains only exactly one more backslash '\', does nothing and returns false.
/// Otherwise returns true.
fn glob_parse_range(
    range_start: char,
    escape_start: bool,
    it: &mut Chars,
    re_pattern: &mut String,
) -> bool {
    match it.as_str().chars().next() {
        None => false,
        Some(']') => {
            if escape_start {
                re_pattern.push('\\');
            }
            re_pattern.push(range_start);
            re_pattern.push('-');
            true
        }
        Some('\\') => {
            it.next();
            if let Some(range_end) = it.next() {
                glob_parse_range_end(range_start, escape_start, range_end, true, re_pattern)
            } else {
                false
            }
        }
        Some(range_end) => {
            it.next();
            glob_parse_range_end(range_start, escape_start, range_end, false, re_pattern)
        }
    }
}

/// Parses a glob-range-expression, and creates the corresponding regex pushing it to re_pattern.
/// The starting opening bracket must have already been consumed by the iterator.
/// Returns true if the iterator starts with a valid glob-range-expression.
/// Otherwise returns false, in which case re_pattern may or may not have been written to.
/// A valid glob-range-expression must be terminated by an unescaped closing bracket ']'.
fn glob_parse_brackets(it: &mut Chars, re_pattern: &mut String) -> bool {
    let peek_first = it.as_str().chars().next();
    if peek_first == Some(']') {
        // a range must contain at least one character
        return false;
    }
    re_pattern.push('[');

    if peek_first == Some('^') {
        it.next();
        re_pattern.push('^');
    }

    while let Some(c) = it.next() {
        match c {
            ']' => {
                re_pattern.push(']');
                return true;
            }
            '\\' => {
                let Some(next) = it.next() else {
                    // a backslash must escape something
                    return false;
                };
                if it.as_str().chars().next() == Some('-') {
                    it.next();
                    if !glob_parse_range(next, true, it, re_pattern) {
                        return false;
                    }
                } else {
                    re_pattern.push('\\');
                    re_pattern.push(next);
                }
            }
            c => {
                if it.as_str().chars().next() == Some('-') {
                    it.next();
                    if !glob_parse_range(c, false, it, re_pattern) {
                        return false;
                    }
                } else {
                    re_pattern.push(c);
                }
            }
        }
    }
    return false;
}

fn glob_to_regex(pattern: &str, prefix: &str) -> Option<(Regex, bool)> {
    let mut re_pattern = String::new();
    re_pattern.reserve(pattern.len());
    let mut it = pattern.chars();

    let mut had_separator = false;
    let mut beginning = &pattern[..pattern.len().min(3)];

    if pattern.chars().next() == Some('/') {
        had_separator = true;
        it.next();
        beginning = &pattern[1..pattern.len().min(4)];
    }

    if beginning == "**/" {
        it.nth(2);
        re_pattern.push_str("(.*/|)");
        had_separator = true;
    }

    let mut last_pos: &str = it.as_str();
    let mut count = 0;
    let mut only_files = false;
    while let Some(c) = it.next() {
        if count > 0 && matches!(c, '*' | '?' | '[' | '\\') {
            re_pattern.push_str(&escape(&last_pos[..count]));
            count = 0;
        }
        match c {
            '/' => {
                had_separator = true;
                let peek_str = it.as_str().chars().as_str();
                let next_three = &peek_str[..peek_str.len().min(3)];

                if next_three != "**" && next_three != "**/" {
                    count += c.len_utf8();
                    continue;
                }

                if count > 0 {
                    re_pattern.push_str(&escape(&last_pos[..count]));
                    count = 0;
                }

                re_pattern.push_str("/.*");
                if next_three == "**" {
                    only_files = true;
                    break;
                }
                re_pattern.push('/');
                it.nth(2);
            }
            '*' => re_pattern.push_str("[^/]*"),
            '?' => re_pattern.push_str("[^/]"),
            '[' => {
                if !glob_parse_brackets(&mut it, &mut re_pattern) {
                    return None;
                }
            }
            '\\' => {
                if !glob_escape_next(&mut it, &mut re_pattern) {
                    return None;
                }
            }
            _ => {
                count += c.len_utf8();
                continue;
            }
        };
        last_pos = it.as_str();
    }

    if count > 0 {
        re_pattern.push_str(&escape(&last_pos[..count]));
    }

    let escaped_prefix = escape(&prefix);
    let last_char = prefix.chars().last();
    let need_extra_separator = last_char != Some('/') && last_char != None;

    let to_reserve = escaped_prefix.len()
        + if need_extra_separator { 1 } else { 0 }
        + if had_separator { 0 } else { "(.*/|)".len() }
        + re_pattern.len()
        + 1;

    let mut full_pattern = String::from_str("^").unwrap();
    full_pattern.reserve(to_reserve);

    full_pattern.push_str(&escaped_prefix);
    if need_extra_separator {
        full_pattern.push('/');
    }
    if !had_separator {
        full_pattern.push_str("(.*/|)");
    }
    full_pattern.push_str(&re_pattern);
    full_pattern.push('$');

    return Some((Regex::new(&full_pattern).unwrap(), only_files));
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
    // .iter()
    // .map(|b| *b)
    // .collect::<Vec<u8>>()
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

        // if overlay.overlay_repo.is_bare() {
        //     return Err(GitOverlayError::BareOverlay);
        // }

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
        for (git_path, file)  in &matching_files {
            println!(
                "{}\n{}", std::str::from_utf8(git_path).unwrap(), file.to_str().unwrap()
            );

            add_to_index(&mut index, GitPathRef::from(git_path.as_slice()), file);
        }
        index.write()?;
        Ok(())
    }
}

fn add_to_index(index: &mut git2::Index, git_path: GitPathRef, file: &Path) {
    // Read file contents into memory
    let file_contents = std::fs::read(file).expect("Failed to read file");
    
    let metadata = std::fs::metadata(file).expect("Failed to get file metadata");

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
            file_size: 0, // Will be calculated by git2
            id: git2::Oid::zero(), // Will be calculated by libgit2
            flags: 0,
            flags_extended: 0,
            path: git_path.to_owned()
        }
    };
    
    // Add the file to the index using its contents
    index.add_frombuffer(&entry, &file_contents).expect("Failed to add file to index");
}

fn ls_files_overlay(paths: Vec<PathBuf>) {
    let Ok(repo) = Repository::open_ext(
        ".",
        RepositoryOpenFlags::CROSS_FS,
        &[] as &[&std::ffi::OsStr],
    ) else {
        println!("Error: Not a git repository");
        return;
    };
    let Some(workdir) = repo.workdir() else {
        println!("Error: Repository has no workdir (likely bare)");
        return;
    };
    let workdir = normalize_path(workdir);
    let git_dir = repo.path();
    let Ok(overlay_repo) = Repository::open(git_dir.join("overlay")) else {
        println!("Error: No overlay exists");
        return;
    };
    if overlay_repo.is_bare() {
        println!("Error: overlay repo is bare");
    }
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
            println!("check {}", std::str::from_utf8(component).unwrap());
            match search.query_until(component) {
                Ok(Answer::Match) | Ok(Answer::PrefixAndMatch) => {
                    println!("found {}", std::str::from_utf8(&entry.path).unwrap());
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

fn sync_overlay_to_base(overlay: &GitOverlay) -> Result<(), GitOverlayError> {
    let overlay_workdir = overlay.overlay_repo.workdir()
        .ok_or_else(|| GitOverlayError::Git2Error(git2::Error::from_str("Overlay repository has no working directory")))?;
    let base_workdir = overlay.base_root();
    
    // Get all files in the overlay index
    let overlay_index = overlay.overlay_repo.index()?;
    
    for entry in overlay_index.iter() {
        let overlay_file_path = git_style_path_to_path(GitPathRef::from(&entry.path));
        let source_path = overlay_workdir.join(&overlay_file_path);
        let dest_path = base_workdir.join(&overlay_file_path);
        
        // Create parent directories if they don't exist
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Copy the file from overlay to base working directory
        if source_path.exists() {
            fs::copy(&source_path, &dest_path)?;
            println!("Synced: {}", overlay_file_path.display());
        }
    }
    
    Ok(())
}

fn post_checkout_hook(target: &str, prev: &str, branch: bool) -> Result<(), GitOverlayError>{
    let overlay = GitOverlay::open(".")?;
    
    // Find the overlay commit associated with the target base commit
    let tag_name = format!("refs/tags/{}", target);
    let overlay_commit = match overlay.overlay_repo.find_reference(&tag_name) {
        Ok(reference) => {
            let object = reference.peel(git2::ObjectType::Commit)?;
            Some(object.into_commit().map_err(|_| git2::Error::from_str("Not a commit"))?)
        }
        Err(_) => {
            // No overlay commit found for this base commit
            println!("No overlay commit found for base commit {}", target);
            return Ok(());
        }
    };
    
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
#[cfg(test)]
mod tests {

    use super::*;

    fn assert_glob_is_regex(glob: &str, expected_re: Option<&str>) {
        let regex = glob_to_regex(glob, "");
        let re_pattern = regex.as_ref().map(|(re, _)| re.as_str());

        assert_eq!(re_pattern, expected_re);
    }

    #[test]
    fn glob_to_regex_test() {
        assert_glob_is_regex("blub", Some("^(.*/|)blub$"));
        assert_glob_is_regex("/blub", Some("^blub$"));
        assert_glob_is_regex("**/blub", Some("^(.*/|)blub$"));
        assert_glob_is_regex("blab/blub", Some("^blab/blub$"));
        assert_glob_is_regex("**/blab/blub", Some("^(.*/|)blab/blub$"));
        assert_glob_is_regex("/**/blab/blub", Some("^(.*/|)blab/blub$"));
        assert_glob_is_regex("blab/blub/**", Some("^blab/blub/.*$"));
        assert_glob_is_regex("blab/**/blub", Some("^blab/.*/blub$"));

        assert_glob_is_regex("blab/*/blub", Some("^blab/[^/]*/blub$"));
        assert_glob_is_regex("blab/*blub", Some("^blab/[^/]*blub$"));
        assert_glob_is_regex("blab/?blub", Some("^blab/[^/]blub$"));

        // double star in path component
        assert_glob_is_regex("**blub", Some("^(.*/|)[^/]*[^/]*blub$"));
        assert_glob_is_regex("/**blub", Some("^[^/]*[^/]*blub$"));
        assert_glob_is_regex("blab/**blub", Some("^blab/[^/]*[^/]*blub$"));
        assert_glob_is_regex("**blub/blab", Some("^[^/]*[^/]*blub/blab$"));

        // remove separator from ranges
        assert_glob_is_regex("/[/-a]", Some("^[0-a]$"));
        assert_glob_is_regex("/[+-/]", Some("^[+-.]$"));
        assert_glob_is_regex("/[+-a]", Some("^[+-.0-a]$"));

        // invalid ranges
        assert_glob_is_regex("[a-+]", None);
        assert_glob_is_regex("[z-a]", None);
        assert_glob_is_regex("[.-+]", None);
        assert_glob_is_regex("[]", None);
        assert_glob_is_regex("[", None);
        assert_glob_is_regex("[\\]", None);

        // other range stuff
        assert_glob_is_regex("/[-a]", Some("^[-a]$"));
        assert_glob_is_regex("/[a-]", Some("^[a-]$"));
        assert_glob_is_regex("/[\\]]", Some("^[\\]]$"));

        // regex escaping
        assert_glob_is_regex(".", Some("^(.*/|)\\.$"));
        assert_glob_is_regex("/.", Some("^\\.$"));
        assert_glob_is_regex("/+", Some("^\\+$"));
        assert_glob_is_regex("/(", Some("^\\($"));
        assert_glob_is_regex("/$", Some("^\\$$"));
        assert_glob_is_regex("/^", Some("^\\^$"));

        // glob and regex escaping
        assert_glob_is_regex("/\\*", Some("^\\*$"));
        assert_glob_is_regex("/\\?", Some("^\\?$"));
        assert_glob_is_regex("/\\[", Some("^\\[$"));
        assert_glob_is_regex("/\\\\", Some("^\\\\$"));

        // glob escaping
        assert_glob_is_regex("/\\blub", Some("^blub$"));
    }
}
