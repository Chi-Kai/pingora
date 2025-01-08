// Copyright 2024 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use async_trait::async_trait;
use clap::Parser;

use bytes::Bytes;
use pingora_core::modules::http::{FilterAction, HttpModules};
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

/// This example shows how to build and import 3rd party modules

/// A simple ACL to check "Authorization: basic $credential" header
mod my_module {
    use super::*;
    use pingora_core::modules::http::{HttpModule, HttpModuleBuilder, Module};
    use pingora_error::{Error, ErrorType::HTTPStatus};
    use std::any::Any;

    // first module
    struct MyAclCtx {}

    #[async_trait]
    impl HttpModule for MyAclCtx {
        async fn request_header_filter(&mut self, req: &mut RequestHeader) -> Result<FilterAction> {
            println!("MyAcl - processing request");

            if let Some(test_action) = req.headers.get("X-Test-Action") {
                match test_action.to_str().unwrap_or("") {
                    "continue" => {
                        println!("MyAcl - continuing");
                        return Ok(FilterAction::Continue);
                    }
                    "response" => {
                        println!("MyAcl - sending custom response");
                        let mut resp = Box::new(ResponseHeader::build(200, None).unwrap());
                        resp.insert_header("X-Test", "custom_response").unwrap();
                        resp.insert_header("Content-Length", "16").unwrap(); // 添加Content-Length
                        return Ok(FilterAction::Response(
                            resp,
                            Some(Bytes::from("Test response body")),
                        ));
                    }
                    "error" => {
                        println!("MyAcl - returning error");
                        return Error::e_explain(HTTPStatus(400), "Test error action");
                    }
                    _ => {}
                }
            }

            Ok(FilterAction::Continue) // 默认继续处理
        }

        // boilerplate code for all modules
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    // This is the singleton object which will be attached to the server
    pub struct MyAcl {}
    impl HttpModuleBuilder for MyAcl {
        // This function defines how to create each Ctx. This function is called when a new request
        // arrives
        fn init(&self) -> Module {
            Box::new(MyAclCtx {})
        }
    }

    // second module
    struct MyLogCtx {}

    // Implement how the module would consume and/or modify request and/or response
    #[async_trait]
    impl HttpModule for MyLogCtx {
        async fn request_header_filter(&mut self, req: &mut RequestHeader) -> Result<FilterAction> {
            let test_action = req.headers.get("X-Test-Action");
            println!("test_action: {:?}", test_action);
            Ok(FilterAction::Continue)
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    // This is the singleton object which will be attached to the server
    pub struct MyLog {}
    impl HttpModuleBuilder for MyLog {
        fn init(&self) -> Module {
            Box::new(MyLogCtx {})
        }
    }
}

pub struct MyProxy;

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    // This function is only called once when the server starts
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        // Add the module to MyProxy
        modules.add_module(Box::new(my_module::MyAcl {}));
        modules.add_module(Box::new(my_module::MyLog {}));
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            ("1.1.1.1", 443),
            true,
            "one.one.one.one".to_string(),
        ));
        Ok(peer)
    }
}

// RUST_LOG=INFO cargo run --example use_module
// curl 127.0.0.1:6193 -H "Host: one.one.one.one" -v
// curl 127.0.0.1:6193 -H "Host: one.one.one.one" -H "Authorization: basic testcode"
// curl 127.0.0.1:6193 -H "Host: one.one.one.one" -H "Authorization: basic wrong" -v
fn main() {
    env_logger::init();

    // read command line arguments
    let opt = Opt::parse();
    let mut my_server = Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let mut my_proxy = pingora_proxy::http_proxy_service(&my_server.configuration, MyProxy);
    my_proxy.add_tcp("0.0.0.0:6193");

    my_server.add_service(my_proxy);
    my_server.run_forever();
}
