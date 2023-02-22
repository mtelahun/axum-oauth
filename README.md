# axum-oauth
![Rust](https://github.com/mtelahun/axum-oauth/actions/workflows/rust.yml/badge.svg)
[![codecov](https://codecov.io/gh/mtelahun/axum-oauth/branch/main/graph/badge.svg?token=A1P9I5E2LU)](https://codecov.io/gh/trevi-software/rhodos)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)


This is a demo application I created to help me understand authentication in rust using OAuth 2.0. Specifically, it shows how to protect your backend APIs using server-side OAuth. It uses the [oxide-auth](https://github.com/HeroicKatora/oxide-auth),
[oxide-auth-async](https://github.com/HeroicKatora/oxide-auth/tree/master/oxide-auth-async), and 
[oxide-auth-axum](https://github.com/HeroicKatora/oxide-auth/tree/master/oxide-auth-axum) crates.
The oxide-auth documentation is a bit sparse and it isn't immediately obvious how to go
about implementing an authentication server with it so I created this demo. As a starting point I used the only example
I could find of an app using Oxide-auth with
the Axum web server: [tf-viewer](https://github.com/danielalvsaaker/tf-viewer/) by 
[@danielalvsaaker](https://github.com/danielalvsaaker).

## Current state
This crate compiles and basically works. However, I haven't done any re-factoring. It is currently in
the "just make it work" stage :grin:.

## Example App
This example app shows a basic OAuth 2.0 authentication life-cycle for API access:

**Note:** I haven't yet implemented a front-end app to show this functionality fully in a browser. See tests for 
full life-cycle example.

- User registration
- Sign-in
- Client registration (public and private)
- Authorization (public and private)
- Protected resource access
- Sign-out

## Internals
[HashMap](https://doc.rust-lang.org/std/collections/struct.HashMap.html) - in-memory implementation of a user database. Also used to create a separate client registration database called __**ClientMap**__.


[async-session](https://docs.rs/async-session/latest/async_session/) - for session management.