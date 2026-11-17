"""A stand-in for the parts of azure-storage-blob's ContainerClient the gateway uses, with the
same errors for the same misuse: write-once uploads, append blobs, sealing, and per-blob
retention that a locked policy only lets grow. It checks the gateway's calls, not Azure's
behaviour, which is confirmed on a real account (standard 11)."""

from types import SimpleNamespace

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError


def _error(code):
    error = HttpResponseError(message=code)
    error.error_code = code
    return error


class FakeContainerClient:
    def __init__(self, *, may_overwrite=True):
        self.blobs = {}
        self.may_overwrite = may_overwrite
        """False as for the gateway's role, which may create blobs (`blobs/add/action`) but not
        write over one (`blobs/write`): Azure then refuses any upload to an existing blob with
        403 UnauthorizedBlobOverwrite, before it looks at overwrite=False."""

    def get_blob_client(self, name):
        return FakeBlobClient(self, name)

    def walk_blobs(self, name_starts_with="", delimiter="/"):
        found = set()
        for name in self.blobs:
            if name.startswith(name_starts_with):
                rest = name[len(name_starts_with) :]
                found.add(
                    name_starts_with + rest.split(delimiter)[0] + delimiter
                    if delimiter in rest
                    else name
                )
        return [SimpleNamespace(name=name) for name in sorted(found)]


class FakeBlobClient:
    def __init__(self, container, name):
        self.container, self.name = container, name

    @property
    def _blob(self):
        blob = self.container.blobs.get(self.name)
        if blob is None:
            raise ResourceNotFoundError(self.name)
        return blob

    def upload_blob(
        self, data, *, overwrite=False, content_settings=None, metadata=None, tags=None, **kw
    ):
        if self.name in self.container.blobs:
            if not self.container.may_overwrite:
                error = _error("UnauthorizedBlobOverwrite")
                error.status_code = 403
                raise error
            if not overwrite:
                raise ResourceExistsError(self.name)
            if self.container.blobs[self.name].policy is not None:
                raise _error("BlobImmutableDueToPolicy")
        self.container.blobs[self.name] = SimpleNamespace(
            data=bytearray(data),
            kind="BlockBlob",
            content_type=content_settings.content_type if content_settings else None,
            metadata=dict(metadata or {}),
            tags=dict(tags or {}),
            sealed=False,
            policy=None,
        )

    def download_blob(self):
        data = bytes(self._blob.data)
        return SimpleNamespace(readall=lambda: data)

    def delete_blob(self):
        if self._blob.policy is not None:
            raise _error("BlobImmutableDueToPolicy")
        del self.container.blobs[self.name]

    def get_blob_properties(self):
        blob = self._blob
        return SimpleNamespace(
            size=len(blob.data),
            metadata=blob.metadata,
            content_settings=SimpleNamespace(content_type=blob.content_type),
            immutability_policy=SimpleNamespace(
                expiry_time=blob.policy.expiry_time if blob.policy else None,
                policy_mode=blob.policy.policy_mode if blob.policy else None,
            ),
            blob_type=blob.kind,
            is_append_blob_sealed=blob.sealed,
        )

    def create_append_blob(self, **kw):
        if self.name in self.container.blobs:
            raise ResourceExistsError(self.name)
        self.upload_blob(b"")
        self.container.blobs[self.name].kind = "AppendBlob"

    def append_block(self, data, **kw):
        blob = self._blob
        if blob.kind != "AppendBlob":
            raise _error("InvalidBlobType")
        if blob.sealed:
            raise _error("BlobIsSealed")
        blob.data.extend(data)

    def seal_append_blob(self, **kw):
        self._blob.sealed = True

    def set_immutability_policy(self, immutability_policy, **kw):
        blob = self._blob
        if (
            blob.policy is not None
            and str(blob.policy.policy_mode) == "Locked"
            and immutability_policy.expiry_time < blob.policy.expiry_time
        ):
            raise _error("ImmutabilityPolicyCannotBeShortened")
        blob.policy = immutability_policy
