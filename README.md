# axum-oauth
![Rust](https://github.com/mtelahun/axum-oauth/actions/workflows/rust.yml/badge.svg)
[![codecov](https://codecov.io/gh/mtelahun/axum-oauth/branch/main/graph/badge.svg?token=A1P9I5E2LU)](https://codecov.io/gh/trevi-software/rhodos)


This is an example repo I created to help me understand authentication in rust using OAuth 2.0. This
application is for server-side OAuth using the [oxide-oauth](https://github.com/HeroicKatora/oxide-auth),
[oxide-auth-async](https://github.com/HeroicKatora/oxide-auth/tree/master/oxide-auth-async), and 
[oxide-auth-axum](https://github.com/HeroicKatora/oxide-auth/tree/master/oxide-auth-axum) crates.
The oxide-auth documentation is a bit sparse and it isn't immediately obvious how to go
about implementing an authentication server with it. As a starting point I used the only example
I could find of an app using Oxide-auth with
the Axum web server: [tf-viewer](https://github.com/danielalvsaaker/tf-viewer/) by 
[@danielalvsaaker](https://github.com/danielalvsaaker).

## Current state
This crate compiles and basically works. However, I haven't done any re-factoring. It is currently in
the "just make it work" stage :grin:.