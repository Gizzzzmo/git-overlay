use git2::Repository;

fn main() {
    let repo = Repository::open(".");
    let repo = repo.unwrap();
    let rev = repo.revparse("HEAD").unwrap();
    let from = rev.from();
    if let Some(obj) = from {
        
        println!("{}", obj.id());
    }
}
