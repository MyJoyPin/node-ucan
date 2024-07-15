use did_functions::*;
use neon::prelude::*;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use ucan_functions::*;

mod did_functions;
mod semantics;
mod ucan_functions;

// Lazily allocate a Tokio runtime to use as the thread pool.
fn runtime<'a, C: Context<'a>>(cx: &mut C) -> NeonResult<&'static Runtime> {
    static RUNTIME: OnceCell<Runtime> = OnceCell::new();

    RUNTIME
        .get_or_try_init(Runtime::new)
        .or_else(|err| cx.throw_error(&err.to_string()))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("createDid", create_did)?;
    cx.export_function("resolveDid", resolve_did)?;
    cx.export_function("restoreDid", restore_did)?;
    cx.export_function("simpleSign", simple_sign)?;
    cx.export_function("simpleVerify", simple_verify)?;
    cx.export_function("invokeUcan", invoke_ucan)?;
    cx.export_function("decodeUcan", decode_ucan)?;
    cx.export_function("verifyUcan", verify_ucan)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ucan::capability::Capabilities;
    use ucan::Ucan;

    #[test]
    fn test_can() {
        let capabilities = Capabilities::try_from(&json!({
           "mailto:username@example.com": {
             "msg/receive": [{}],
             "msg/send": [{ "draft": true }, { "publish": true, "topic": ["foo"]}]
        }
        }))
        .unwrap();
        let resource = capabilities.get("mailto:username@example.com").unwrap();
        assert_eq!(resource.get("msg/receive").unwrap(), &vec![json!({})]);
        assert_eq!(
            resource.get("msg/send").unwrap(),
            &vec![
                json!({ "draft": true }),
                json!({ "publish": true, "topic": ["foo"] })
            ]
        );
    }

    #[test]
    fn test_decode() {
        let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkaWQ6a2V5OnphYmNkZS4uLiIsImNhcCI6eyJtYWlsdG86dXNlcm5hbWVAZXhhbXBsZS5jb20iOnsibXNnL3JlY2VpdmUiOlt7fV0sIm1zZy9zZW5kIjpbeyJkcmFmdCI6dHJ1ZX0seyJwdWJsaXNoIjp0cnVlLCJ0b3BpYyI6WyJmb28iXX1dfX0sImV4cCI6MTcyMTAzMjcyNSwiZmN0Ijp7ImEiOiJiIn0sImlzcyI6ImRpZDprZXk6ejZNa3JNMUhqdVJ4amRWNVU2czR3UnJOV2RaR1V5aU02RUZ3SjhYUm1xOG4ybng3Iiwibm5jIjoic2pCYnB2OXlNS2JJMlhWaDduREhsRUZ0U1I2TS0zTVU0QVdGSmhXWDlyWSIsInVjdiI6IjAuMTAuMC1jYW5hcnkifQ.0b8kVA0NfsYPdSRT6YM-5u6KgcjWsu2rtQKwsdi2_N3S0Coo5qPGajD1T8-lkcJ9ls8jj_6ipPYbtlq2IQkXAQ";
        let ucan = Ucan::try_from(token).unwrap();
        println!("ucan={:#?}", ucan);
    }
}
