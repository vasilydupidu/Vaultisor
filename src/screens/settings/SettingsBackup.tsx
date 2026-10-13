import { useEffect, useRef, useState } from "react";
import { AlertTriangle, Download, FileText, RefreshCw, Upload } from "lucide-react";
import { useTranslation, Trans } from 'react-i18next';
import {
  apiBackupGetConfig,
  apiBackupSetConfig,
  apiBackupNow,
  apiVaultExport,
  apiVaultRestore,
  apiPrepareFile,
  apiImportChromiumCsv,
  apiSecureDeleteFile,
  apiRecordsBatchDelete,
  type BackupConfig,
  type RejectedCsvRow,
} from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { useToast } from "@/components/ui/Toast";
import { isAuthCancelled, useSecurityConfirm } from "@/components/SecurityConfirm";
import { cn } from "@/lib/cn";
import { RetryableRequest } from "@/lib/requestId";
import { sanitizeError } from "@/lib/sanitizeError";
import { formatDateTime } from "@/lib/format";
import { Section } from "./controls";

export function SettingsBackup() {
  const { t } = useTranslation();
  const [backupCfg, setBackupCfg] = useState<BackupConfig | null>(null);
  const toast = useToast();
  const authorized = useSecurityConfirm();
  // Повтор «создать копию» после ошибки не создаёт вторую копию.
  const backupRequest = useRef(new RetryableRequest());

  const refreshBackup = () => {
    apiBackupGetConfig().then(setBackupCfg).catch(() => setBackupCfg(null));
  };

  useEffect(() => {
    refreshBackup();
  }, []);

  const handlePickBackupDir = async () => {
    const freq = backupCfg?.frequency || "off";
    try {
      const capability = await apiPrepareFile("backup_directory");
      await authorized("change_backup_directory", () => apiBackupSetConfig(capability, freq));
      refreshBackup();
      toast.success(t('settingsBackup.dirSaved'));
    } catch (e) {
      if (isAuthCancelled(e)) return;
      toast.error(t('settingsBackup.dirSaveError', { error: sanitizeError(e, "") }));
    }
  };

  const handleSetBackupFreq = async (frequency: string) => {
    try {
      await apiBackupSetConfig(null, frequency);
      refreshBackup();
    } catch (e) {
      toast.error(t('settingsBackup.freqSaveError', { error: sanitizeError(e, "") }));
    }
  };

  const handleBackupNow = async () => {
    if (!backupCfg?.dir) {
      toast.error(t('settingsBackup.dirNotSelected'));
      return;
    }
    try {
      await apiBackupNow(backupRequest.current.idFor("backup-now"));
      backupRequest.current.done();
      refreshBackup();
      toast.success(t('settingsBackup.backupCreated'));
    } catch (e) {
      toast.error(t('settingsBackup.backupError', { error: sanitizeError(e, "") }));
    }
  };

  // `window.confirm` — нелокализованный системный диалог, который к
  // тому же блокирует поток webview. Подтверждение показываем своей карточкой.
  const [confirmRestore, setConfirmRestore] = useState(false);
  const [exportPassword, setExportPassword] = useState("");
  const [exporting, setExporting] = useState(false);

  const handleRestore = async () => {
    setConfirmRestore(false);
    try {
      const capability = await apiPrepareFile("restore");
      await authorized("restore_backup", () => apiVaultRestore(capability));
      toast.success(t('settingsBackup.restored'));
      setTimeout(() => window.location.reload(), 900);
    } catch (e) {
      if (isAuthCancelled(e)) return;
      toast.error(sanitizeError(e, t('settingsBackup.restoreError')));
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const capability = await apiPrepareFile("export");
      const password = exportPassword.trim() || undefined;
      await authorized("export_vault", () => apiVaultExport(capability, password));
      setExportPassword("");
      toast.success(t('settingsBackup.exportSuccess'));
    } catch (e) {
      if (isAuthCancelled(e)) return;
      toast.error(sanitizeError(e));
    } finally {
      setExporting(false);
    }
  };

  const [importedDeletionToken, setImportedDeletionToken] = useState<string | null>(null);
  const [importedRecordIds, setImportedRecordIds] = useState<string[]>([]);
  const [rejectedRows, setRejectedRows] = useState<RejectedCsvRow[]>([]);

  const handleImportCsv = async () => {
    try {
      const res = await apiImportChromiumCsv();
      if (res.rejected.length > 0) {
        toast.error(
          t('settingsBackup.importPartial', {
            imported: res.imported,
            total: res.total,
            rejected: res.rejected.length,
          }),
        );
      } else {
        toast.success(t('settingsBackup.importSuccess', { count: res.imported }));
      }
      setRejectedRows(res.rejected);
      setImportedDeletionToken(res.deletion_token);
      setImportedRecordIds(res.imported_ids);
    } catch (e) {
      toast.error(sanitizeError(e, t('settingsBackup.importError', { error: "" })));
    }
  };

  const handleSecureDeleteCsv = async () => {
    if (!importedDeletionToken) return;
    try {
      await apiSecureDeleteFile(importedDeletionToken);
      toast.success(t('settingsBackup.deleteCsvSuccess'));
      setImportedDeletionToken(null);
    } catch (e) {
      toast.error(sanitizeError(e, ""));
    }
  };

  const handleUndoImport = async () => {
    if (importedRecordIds.length === 0) return;
    try {
      await apiRecordsBatchDelete("web", importedRecordIds);
      toast.success(t('settingsBackup.undoImportSuccess'));
      setImportedRecordIds([]);
    } catch (e) {
      toast.error(sanitizeError(e, ""));
    }
  };

  return (
    <Section title={t('settingsBackup.title')}>
      <p className="text-2xs text-white/50 leading-snug">
        {t('settingsBackup.desc')}
      </p>

      <div className="text-2xs text-white/70">
        <strong>{t('settingsBackup.dirLabel')}</strong>{" "}
        <span className="break-all">{backupCfg?.dir || t('settingsBackup.notSelected')}</span>
      </div>
      {backupCfg?.last_backup && (
        <div className="text-2xs text-white/50">
          {t('settingsBackup.lastBackup', { time: formatDateTime(backupCfg.last_backup) })}
        </div>
      )}

      <Button variant="secondary" size="sm" fullWidth onClick={handlePickBackupDir}>
        {backupCfg?.dir ? t('settingsBackup.changeDir') : t('settingsBackup.selectDir')}
      </Button>

      <div className="grid grid-cols-3 gap-1.5">
        {[
          { v: "off", l: t('settingsBackup.freqManual') },
          { v: "daily", l: t('settingsBackup.freqDaily') },
          { v: "weekly", l: t('settingsBackup.freqWeekly') },
        ].map((o) => {
          const active = (backupCfg?.frequency ?? "off") === o.v;
          return (
            <button
              key={o.v}
              type="button"
              onClick={() => handleSetBackupFreq(o.v)}
              className={cn(
                "px-2 py-1.5 rounded-lg text-xs transition-app text-center border",
                active
                  ? "bg-brand-500/15 text-brand-300 border-brand-500/40"
                  : "bg-white/2 text-white/55 border-white/6 hover:bg-white/5",
              )}
            >
              {o.l}
            </button>
          );
        })}
      </div>

      <Button
        variant="secondary"
        size="sm"
        fullWidth
        onClick={handleBackupNow}
      >
        {t('settingsBackup.backupNow')}
      </Button>
      <p className="text-2xs text-white/40 leading-snug">
        {t('settingsBackup.scheduleHint')}
      </p>

      <div className="border-t border-white/6" />
      <p className="text-2xs text-white/50 leading-snug">
        <strong>{t('settingsBackup.exportTitle')}</strong>{" "}
        {t('settingsBackup.exportDesc')}
      </p>
      <Input
        type="password"
        autoComplete="new-password"
        value={exportPassword}
        onChange={(e) => setExportPassword(e.target.value)}
        placeholder={t('settingsBackup.exportPasswordPlaceholder')}
        disabled={exporting}
      />
      <Button
        variant="secondary"
        size="sm"
        fullWidth
        loading={exporting}
        onClick={handleExport}
        leftIcon={<Upload className="h-3.5 w-3.5" />}
      >
        {t('settingsBackup.exportBtn')}
      </Button>

      <div className="border-t border-white/6" />
      <p className="text-2xs text-white/50 leading-snug">
        <strong>{t('settingsBackup.importBrowserTitle')}</strong>{" "}
        {t('settingsBackup.importBrowserDesc')}
      </p>
      <Button
        variant="secondary"
        size="sm"
        fullWidth
        onClick={handleImportCsv}
        leftIcon={<Download className="h-3.5 w-3.5" />}
      >
        {t('settingsBackup.importBrowserBtn')}
      </Button>

      {importedDeletionToken && (
        <div className="card-flat p-3 space-y-2 border-warning/40 bg-warning/5 animate-fade-in">
          <div className="text-xs font-medium text-warning flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5" />
            {t('settingsBackup.deleteCsvTitle')}
          </div>
          <p className="text-2xs text-white/60 leading-snug">
            {t('settingsBackup.deleteCsvDesc')}
          </p>
          <div className="flex gap-2 pt-1">
            <Button
              variant="danger"
              size="sm"
              fullWidth
              onClick={handleSecureDeleteCsv}
            >
              {t('settingsBackup.deleteCsvBtn')}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              fullWidth
              onClick={() => setImportedDeletionToken(null)}
            >
              {t('settingsBackup.keepCsvBtn')}
            </Button>
          </div>

        </div>
      )}

      {rejectedRows.length > 0 && (
        <div className="card-flat p-3 space-y-1.5 border-danger/40 bg-danger/5 animate-fade-in">
          <div className="text-xs font-medium text-danger">
            {t('settingsBackup.rejectedTitle', { count: rejectedRows.length })}
          </div>
          <ul className="text-2xs text-white/60 leading-snug space-y-0.5 max-h-32 overflow-y-auto">
            {rejectedRows.map((r) => (
              <li key={r.row}>
                {t('settingsBackup.rejectedRow', { row: r.row, site: r.site, reason: r.reason })}
              </li>
            ))}
          </ul>
        </div>
      )}

      {importedRecordIds.length > 0 && (
        <Button variant="secondary" size="sm" fullWidth onClick={handleUndoImport}>
          {t('settingsBackup.undoImportBtn', { count: importedRecordIds.length })}
        </Button>
      )}

      <div className="border-t border-white/6" />
      <p className="text-2xs text-white/50 leading-snug">
        <strong>{t('settingsBackup.restoreTitle')}</strong>{" "}
        <Trans i18nKey="settingsBackup.restoreDesc" components={{ code: <code /> }} />
      </p>
      <Button
        variant="secondary"
        size="sm"
        fullWidth
        onClick={() => setConfirmRestore(true)}
        leftIcon={<RefreshCw className="h-3.5 w-3.5" />}
      >
        {t('settingsBackup.restoreBtn')}
      </Button>

      {confirmRestore && (
        <div className="card-flat p-3 space-y-2 border-warning/40 bg-warning/5 animate-fade-in">
          <div className="text-xs font-medium text-warning flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            {t('settingsBackup.restoreConfirmTitle')}
          </div>
          <p className="text-2xs text-white/60 leading-snug">
            {t('settingsBackup.restoreConfirm')}
          </p>
          <div className="flex gap-2 pt-1">
            <Button variant="danger" size="sm" fullWidth onClick={handleRestore}>
              {t('common.confirm')}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              fullWidth
              onClick={() => setConfirmRestore(false)}
            >
              {t('common.cancel')}
            </Button>
          </div>
        </div>
      )}
    </Section>
  );
}
