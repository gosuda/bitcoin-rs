# Developer overview page

`index.html` is a self-contained developer introduction to bitcoin-rs. It links
to source and normative contracts and offers a source-reviewed local regtest
walkthrough. It is not a new source of architecture or validation policy.

Open the HTML file directly in a browser, or preview it from the repository
root with Python 3:

```sh
python3 -m http.server 8000 --bind 127.0.0.1 --directory docs/site
```

Then open <http://127.0.0.1:8000/>. Stop the server with Ctrl-C.

There is no build step, package manager, third-party asset, analytics, sign-up
backend, or deployment workflow. Adding these files does not publish a website
or enable GitHub Pages. The module links work without JavaScript; filtering and
command copying are progressive enhancements. When clipboard access is denied,
the page selects the commands for manual copying.

Source links and the command checkout use one explicit commit. When updating
that reference, review the workspace, build options, interface contracts, and
benchmark status together. Do not change the pin alone or turn unexecuted
commands into a successful-run claim. Keep browser and runtime acceptance
results in the reviewing PR or CI artifacts, not in this source directory.
