#!/bin/bash
pip install conan
conan remote add url https://bincrafters.jfrog.io/artifactory/api/conan/public-conan
conan config set general.revisions_enabled=1