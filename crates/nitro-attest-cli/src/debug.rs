use clap::Subcommand;

#[derive(Subcommand)]
pub enum DebugCli {}

impl DebugCli {
    pub fn run(&self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
