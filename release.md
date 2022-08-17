# Binaries

- Push a tag in the form `vX.X.X`
  - goreleaser creates a github release
  - GHA builds and pushes to dockerhub

# Helm chart

- Submit a PR to update the chart version
  - (optional) update the image versions to the latest docker image
  