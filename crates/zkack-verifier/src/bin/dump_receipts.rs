use anyhow::Result;

fn main() -> Result<()> {
    let db = sled::open("./data/receipts")?;
    let mut n = 0usize;
    for kv in db.iter() {
        let (_k, v) = kv?;
        println!("{}", String::from_utf8_lossy(&v));
        n += 1;
    }
    eprintln!("-- {} receipt(s)", n);
    Ok(())
}
