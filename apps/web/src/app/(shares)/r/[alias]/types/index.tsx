import { GetReverseShareForUploadResult } from "@/http/endpoints/reverse-shares/types";
import { FILE_STATUS } from "../constants";

export type ReverseShareInfo = GetReverseShareForUploadResult["data"]["reverseShare"];
export type FileStatus = (typeof FILE_STATUS)[keyof typeof FILE_STATUS];

export interface DefaultLayoutProps {
  reverseShare: ReverseShareInfo | null;
  password: string;
  alias: string;
  isMaxFilesReached: boolean;
  hasUploadedSuccessfully: boolean;
  onUploadSuccess: () => void;
  isLinkInactive: boolean;
  isLinkNotFound: boolean;
  isLinkExpired: boolean;
}

export interface FileUploadSectionProps {
  reverseShare: ReverseShareInfo;
  password: string;
  alias: string;
  onUploadSuccess?: () => void;
}

export interface FileWithProgress {
  file: File;
  progress: number;
  status: FileStatus;
  error?: string;
}

export interface PasswordModalProps {
  isOpen: boolean;
  // Caller may run an async submit (we await it to keep the spinner
  // visible until the network call resolves), so allow a
  // Promise-returning implementation as well as a fire-and-forget
  // one.
  onSubmit: (password: string) => void | Promise<unknown>;
  onClose: () => void;
}

export interface WeTransferLayoutProps {
  reverseShare: ReverseShareInfo | null;
  password: string;
  alias: string;
  isMaxFilesReached: boolean;
  hasUploadedSuccessfully: boolean;
  onUploadSuccess: () => void;
  isLinkInactive: boolean;
  isLinkNotFound: boolean;
  isLinkExpired: boolean;
}
