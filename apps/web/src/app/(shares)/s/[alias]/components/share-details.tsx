import { useState } from "react";
import { IconDownload, IconFolderOff, IconShare, IconTerminal2 } from "@tabler/icons-react";
import { format } from "date-fns";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { FilesViewManager } from "@/app/files/components/files-view-manager";
import { FilePreviewModal } from "@/components/modals/file-preview-modal";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ShareDetailsProps } from "../types";

interface File {
  id: string;
  name: string;
  description?: string;
  extension: string;
  size: number;
  objectName: string;
  userId: string;
  folderId?: string;
  createdAt: string;
  updatedAt: string;
}

interface Folder {
  id: string;
  name: string;
  description?: string;
  objectName: string;
  parentId?: string;
  userId: string;
  createdAt: string;
  updatedAt: string;
  totalSize?: string;
  _count?: {
    files: number;
    children: number;
  };
}

interface ShareDetailsPropsExtended extends Omit<ShareDetailsProps, "onBulkDownload"> {
  onBulkDownload?: () => Promise<void>;
  onSelectedItemsBulkDownload?: (files: File[], folders: Folder[]) => Promise<void>;
  folders: Folder[];
  files: File[];
  path: Folder[];
  isBrowseLoading: boolean;
  searchQuery: string;
  navigateToFolder: (folderId?: string) => void;
  handleSearch: (query: string) => void;
}

// shellQuote wraps a string in single quotes for safe POSIX shell
// pasting. Embedded single quotes are escaped as `'\''` (close, escape,
// reopen). Used for the curl command surfaced by handleCopyCurl —
// share names, passwords, and filenames can carry spaces, quotes, $,
// etc. Declared at module scope so eslint's no-use-before-define
// rule is happy.
function shellQuote(s: string): string {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

export function ShareDetails({
  share,
  password,
  onDownload,
  onBulkDownload,
  onSelectedItemsBulkDownload,
  folders,
  files,
  path,
  isBrowseLoading,
  searchQuery,
  navigateToFolder,
  handleSearch,
}: ShareDetailsPropsExtended) {
  const t = useTranslations();
  const [isPreviewOpen, setIsPreviewOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<{ name: string; objectName: string; type?: string } | null>(null);

  const shareHasItems = (share.files && share.files.length > 0) || (share.folders && share.folders.length > 0);
  const totalShareItems = (share.files?.length || 0) + (share.folders?.length || 0);
  const hasMultipleFiles = totalShareItems > 1;

  const handleFolderDownload = async (folderId: string, folderName: string) => {
    // Use the download handler from the hook which uses toast.promise
    await onDownload(`folder:${folderId}`, folderName);
  };

  // The same /s/{alias} URL the user is reading now also serves
  // direct downloads to non-HTML clients (curl, wget) — see the
  // ServeDownload handler in apps/server/internal/modules/share/share.go.
  // We surface the ready-to-paste curl command here so non-technical
  // visitors don't have to know the trick exists. The current URL is
  // already correct (window.location); we just attach `-L` (follow
  // the 302 to S3 when the share is a single file), an output flag
  // tied to the share's name, and `-u :<password>` when applicable.
  const handleCopyCurl = async () => {
    if (typeof window === "undefined") return;
    const shareURL = window.location.origin + window.location.pathname.replace(/\/$/, "");
    // Multi-file shares stream a zip; single-file shares 302 to the
    // file. Pick a sensible filename for the -o flag in both cases.
    const outName = hasMultipleFiles
      ? `${share.name || "share"}.zip`
      : share.files?.[0]
        ? `${share.files[0].name}.${share.files[0].extension}`
        : "download";
    const pwdFlag = password ? ` -u :${shellQuote(password)}` : "";
    const cmd = `curl -L${pwdFlag} -o ${shellQuote(outName)} ${shellQuote(shareURL)}`;
    try {
      await navigator.clipboard.writeText(cmd);
      toast.success(t("share.curlCopied"));
    } catch (err) {
      console.error("clipboard write failed", err);
      toast.error(t("share.curlCopyFailed"));
    }
  };

  return (
    <>
      <Card>
        <CardContent>
          <div className="flex flex-col gap-6">
            <div className="flex flex-col gap-2">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="flex items-center gap-2">
                  <IconShare className="w-6 h-6 text-muted-foreground" />
                  <h1 className="text-2xl font-semibold">{share.name || t("share.details.untitled")}</h1>
                </div>
                {shareHasItems && (
                  <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
                    {hasMultipleFiles && (
                      <Button onClick={onBulkDownload} className="flex items-center gap-2 w-full sm:w-auto">
                        <IconDownload className="w-4 h-4" />
                        {t("share.downloadAll")}
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      onClick={handleCopyCurl}
                      className="flex items-center gap-2 w-full sm:w-auto"
                      title={t("share.copyCurlTooltip")}
                    >
                      <IconTerminal2 className="w-4 h-4" />
                      {t("share.copyCurl")}
                    </Button>
                  </div>
                )}
              </div>
              {share.description && <p className="text-muted-foreground">{share.description}</p>}
              <div className="flex gap-4 text-sm text-muted-foreground">
                <span>
                  {t("share.details.created", {
                    date: format(new Date(share.createdAt), "MM/dd/yyyy HH:mm"),
                  })}
                </span>
                {share.expiration && (
                  <span>
                    {t("share.details.expires", {
                      date: format(new Date(share.expiration), "MM/dd/yyyy HH:mm"),
                    })}
                  </span>
                )}
              </div>
            </div>

            <FilesViewManager
              files={files}
              folders={folders}
              searchQuery={searchQuery}
              onSearch={handleSearch}
              onDownload={onDownload}
              onBulkDownload={onSelectedItemsBulkDownload}
              isLoading={isBrowseLoading}
              isShareMode={true}
              emptyStateComponent={() => (
                <div className="text-center py-16">
                  <div className="flex justify-center mb-6">
                    <IconFolderOff className="h-24 w-24 text-muted-foreground/30" />
                  </div>
                  <h3 className="text-lg font-semibold text-foreground mb-2">{t("fileSelector.noFilesInShare")}</h3>
                  <p className="text-muted-foreground max-w-sm mx-auto">{t("files.empty.description")}</p>
                </div>
              )}
              breadcrumbs={
                <Breadcrumb>
                  <BreadcrumbList>
                    <BreadcrumbItem>
                      <BreadcrumbLink
                        className="flex items-center gap-1 cursor-pointer"
                        onClick={() => navigateToFolder()}
                      >
                        <IconShare size={16} />
                        {t("folderActions.rootFolder")}
                      </BreadcrumbLink>
                    </BreadcrumbItem>

                    {path.map((folder, index) => (
                      <div key={folder.id} className="contents">
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                          {index === path.length - 1 ? (
                            <BreadcrumbPage>{folder.name}</BreadcrumbPage>
                          ) : (
                            <BreadcrumbLink className="cursor-pointer" onClick={() => navigateToFolder(folder.id)}>
                              {folder.name}
                            </BreadcrumbLink>
                          )}
                        </BreadcrumbItem>
                      </div>
                    ))}
                  </BreadcrumbList>
                </Breadcrumb>
              }
              onNavigateToFolder={navigateToFolder}
              onDownloadFolder={handleFolderDownload}
              onPreview={(file) => {
                setSelectedFile({ name: file.name, objectName: file.objectName });
                setIsPreviewOpen(true);
              }}
            />
          </div>
        </CardContent>
      </Card>

      {selectedFile && (
        <FilePreviewModal
          isOpen={isPreviewOpen}
          onClose={() => {
            setIsPreviewOpen(false);
            setSelectedFile(null);
          }}
          file={selectedFile}
          sharePassword={password}
        />
      )}
    </>
  );
}
