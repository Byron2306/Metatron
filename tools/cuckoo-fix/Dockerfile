FROM blacktop/cuckoo:2.0

# Run as root to allow pip install
USER root

# Upgrade pip and pymongo to support modern MongoDB servers (>=6/7)
RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir --upgrade pymongo dnspython

# Create a small compatibility dist-info so pkg_resources satisfied Cuckoo's
# strict dependency on pymongo==3.0.3 while the runtime uses the newer pymongo.
RUN PYTHON_SITE_PACKAGES=$(python -c "import site,sys; print([p for p in site.getsitepackages() if 'site-packages' in p][0])") \
    && mkdir -p "$PYTHON_SITE_PACKAGES/pymongo-3.0.3.dist-info" \
    && printf "Metadata-Version: 1.1\nName: pymongo\nVersion: 3.0.3\n" > "$PYTHON_SITE_PACKAGES/pymongo-3.0.3.dist-info/METADATA" || true

# Ensure permissions remain correct (blacktop image uses root by default)
USER root

# Entrypoint and CMD are inherited from base image

LABEL maintainer="seraph-maintainer"
