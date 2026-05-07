"""SD-WAN external controller probe (no credentials, OpenSSL + TLS)."""

try:
    from ._version import version as __version__
except Exception:  # pragma: no cover
    # Fallback for editable/source installs where _version.py may be absent.
    try:
        from importlib.metadata import PackageNotFoundError, version

        __version__ = version("sdwan-probe")
    except Exception:
        __version__ = "0.0.0+unknown"
