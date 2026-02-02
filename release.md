# Docker Image/Binaries

First build the docker image, github release and release artifacts.

- Push a tag in the form `vX.X.X` to the commit that you want to cut the release on.
  - goreleaser creates a draft github release.
      - Find it [here](https://github.com/joe-elliott/cert-exporter/releases).
      - Clean up the release notes. For instance the previous helm chart commit is often included and should be removed.
      - Add a line "Thanks to <contributors> for the help!"
  - GHA builds and pushes to dockerhub
      - Confirm that the [image appears](https://hub.docker.com/r/joeelliott/cert-exporter) here.

# Helm chart

After the docker image is cut and the release exists. We need to build the helm chart.

- Submit a PR to update the chart version [like this](https://github.com/joe-elliott/cert-exporter/pull/235).
  - (optional) Update the image versions to the latest docker image. This may not be required if the only changes were to the helm chart.
- The new chart version will automatically force a build.
  - Use helm locally to confirm the build occurred and is available.
    ```
    helm repo update cert-exporter
    helm search repo cert-exporter
    ```

  