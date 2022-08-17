# Binaries

- Push a tag in the form `vX.X.X`
  - goreleaser creates a github release
  - GHA builds and pushes to dockerhub

# Helm chart

- (optional) Submit a PR which updates the image versions to the latest docker image
- Push a tag in the form `cert-exporter-X.X.X`