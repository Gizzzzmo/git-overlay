use clap::{Parser, Subcommand};
use git2::{ObjectType, TreeWalkMode, TreeWalkResult};
use std::fs::OpenOptions;
use std::io::Write;
use std::{os::unix::fs::OpenOptionsExt, path::PathBuf};

mod overlay;
use overlay::{git_style_path_to_path, GitOverlay, GitOverlayError, GitPathRef};

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
    /// List all files in the overlay's index, underneath the given paths
    LsFiles { paths: Vec<PathBuf> },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { remote } => init_overlay(remote),
        Commands::Import { url } => import_overlay(url),
        Commands::Add { paths } => add_to_overlay(paths),
        Commands::CommitHook {} => post_commit(),
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
    overlay.add(paths).unwrap();
}

fn ls_files_overlay(paths: Vec<PathBuf>) {
    let overlay = GitOverlay::open(".").unwrap();
    overlay.ls_files(paths).unwrap();
}

fn init_overlay(remote: Option<String>) {
    GitOverlay::init(".", remote.as_ref().map(|url| (url.as_str(), false))).unwrap();
}

fn import_overlay(url: String) {
    GitOverlay::init(".", Some((url.as_str(), true))).unwrap();
}
fn post_commit() {
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

fn post_checkout_hook(target: &str, _prev: &str, _branch: bool) -> Result<(), GitOverlayError> {
    let overlay = GitOverlay::open(".").unwrap();

    // Find the overlay commit associated with the target base commit
    let tag_name = format!("refs/tags/{}", target);
    let reference = overlay.overlay_repo.find_reference(&tag_name)?;
    let object = reference.peel(git2::ObjectType::Commit)?;
    let commit = object
        .into_commit()
        .map_err(|_| git2::Error::from_str("Not a commit"))?;

    println!("{}", commit.id().to_string());

    // walk the commit's tree and write the trees files into the base repo
    commit.tree()?.walk(TreeWalkMode::PreOrder, |x, node| {
        println!("hi: {} {} {:?}", x, node.name().unwrap(), node.name_bytes());
        let path = GitPathRef::from(node.name_bytes());
        let path2 = GitPathRef::from(node.name_bytes());
        let attribute = node.filemode();
        let syspath = overlay
            .base_root()
            .join(x)
            .join(git_style_path_to_path(path2));

        if node.kind() == Some(ObjectType::Tree) {
            println!("alidsjas");
            _ = std::fs::remove_file(&syspath);
            _ = std::fs::create_dir(syspath);
            return TreeWalkResult::Ok;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(attribute as u32)
            .open(syspath);

        let Ok(bytes) = node.to_object(&overlay.overlay_repo).unwrap().into_blob() else {
            return TreeWalkResult::Ok;
        };

        _ = file.unwrap().write_all(bytes.content());
        return TreeWalkResult::Ok;
    })?;

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
