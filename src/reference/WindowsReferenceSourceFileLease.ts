import type { ArtifactResourceOwner } from "../artifacts/ArtifactResourceScope.js";
import {
  requireWindowsNativeAuthority,
  windowsFileIdentitySchema,
  windowsHandleSchema,
} from "../windows/WindowsNativeLoader.js";

const admittedFileSchema = windowsFileIdentitySchema.extend({
  handle: windowsHandleSchema,
});

/** Retain native no-reparse admission until the Node descriptor and read checks settle. */
export const acquireWindowsReferenceSourceFileLease = (
  path: string,
): ArtifactResourceOwner => {
  const authority = requireWindowsNativeAuthority();
  const admitted = admittedFileSchema.parse(authority.call("open", [path]));
  let released = false;
  return {
    kind: "lease",
    resource: path,
    lease: {
      async release() {
        if (released) return;
        authority.call("close", [admitted.handle]);
        released = true;
      },
    },
  };
};
