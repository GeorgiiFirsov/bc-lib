# [Choice] Debian / Ubuntu version (use Debian 11, Ubuntu 18.04/22.04 on local arm64/Apple Silicon): debian-11, debian-10, ubuntu-22.04, ubuntu-20.04, ubuntu-18.04
ARG VARIANT=debian-11
FROM --platform=linux/amd64 mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT}

# Run configuration script
ADD ./configure.sh /tmp/
RUN sudo chmod +x /tmp/configure.sh \
   && sudo /tmp/configure.sh \
   && sudo rm -f /tmp/configure.sh

# [Optional] Uncomment this section to install additional vcpkg ports.
# RUN su vscode -c "${VCPKG_ROOT}/vcpkg install <your-port-name-here>"
