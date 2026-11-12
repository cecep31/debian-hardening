#!/usr/bin/env bash
# Fetches the OpenSCAP content (SCAP datastream) for Debian 13 once and caches it.
# Debian's own ssg-debian package (0.1.76) only covers Debian 11/12, so the content
# comes from the upstream ComplianceAsCode release, pinned by version and SHA-512.
# Prints the path of the cached datastream.
set -euo pipefail

SSG_VERSION="0.1.82"
SSG_SHA512="1caea418f0a5aaef7025e1655ca45a80942ea87ee832b943644ba6f9991b14a6ac5b35dddcd04b754e1fc8fbdee7b7f394507d24b123e821cca0354dc4e03cfd"
DS_NAME="ssg-debian13-ds.xml"

CACHE_DIR="$(cd "$(dirname "$0")" && pwd)/.cache"
DS_PATH="${CACHE_DIR}/ssg-${SSG_VERSION}-${DS_NAME}"
ZIP_PATH="${CACHE_DIR}/scap-security-guide-${SSG_VERSION}.zip"
URL="https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip"

if [ -s "${DS_PATH}" ]; then
  echo "${DS_PATH}"
  exit 0
fi

mkdir -p "${CACHE_DIR}"
if ! { [ -f "${ZIP_PATH}" ] && echo "${SSG_SHA512}  ${ZIP_PATH}" | sha512sum -c --status; }; then
  echo "==> downloading scap-security-guide ${SSG_VERSION} (~180 MB, once)" >&2
  curl -fL --retry 3 -o "${ZIP_PATH}.part" "${URL}"
  mv "${ZIP_PATH}.part" "${ZIP_PATH}"
  echo "${SSG_SHA512}  ${ZIP_PATH}" | sha512sum -c --status \
    || { echo "FAIL: checksum mismatch for ${ZIP_PATH}" >&2; rm -f "${ZIP_PATH}"; exit 1; }
fi

# Extract only the Debian 13 datastream, then drop the large zip.
python3 -I - "${ZIP_PATH}" "${DS_NAME}" "${DS_PATH}" <<'PY'
import shutil, sys, zipfile
zip_path, name, out = sys.argv[1:]
with zipfile.ZipFile(zip_path) as z:
    member = next(m for m in z.namelist() if m.endswith("/" + name))
    with z.open(member) as src, open(out + ".part", "wb") as dst:
        shutil.copyfileobj(src, dst)
PY
mv "${DS_PATH}.part" "${DS_PATH}"
rm -f "${ZIP_PATH}"

echo "${DS_PATH}"
