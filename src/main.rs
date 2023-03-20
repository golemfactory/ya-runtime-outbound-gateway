mod gateway;
mod routing;
mod iptables;

use gateway::OutboundGatewayRuntime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ya_runtime_sdk::run::<OutboundGatewayRuntime>().await
}
