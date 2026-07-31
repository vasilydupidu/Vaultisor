import { useEffect, useState } from "react";
import { Download, FileText, RefreshCw } from "lucide-react";
import { useTranslation, Trans } from 'react-i18next';
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  apiBackupGetConfig,
  apiBackupSetConfig,
  apiBackupNow,
  apiVaultRestore,
  apiImportChromiumCsv,
  apiSecureDeleteFile,
  apiRecordsBatchDelete,
  type BackupConfig,
} from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { useToast } from "@/components/ui/Toast";
import { cn } from "@/lib/cn";
import { sanitizeError } from "@/lib/sanitizeError";
import { Section } from "./controls";

export function SettingsBackup() {
  const { t } = useTranslation();
  const [backupCfg, setBackupCfg] = useState<BackupConfig | null>(null);
  const toast = useToast();

  const refreshBackup = () => {
    apiBackupGetConfig().then(setBackupCfg).catch(() => setBackupCfg(null));
  };

  useEffect(() => {
    refreshBackup();
  }, []);

  const handlePickBackupDir = async () => {
    const dir = await openDialog({ directory: true, title: t('settingsBackup.dirDialogTitle') });
    if (typeof dir !== "string") return;
    const freq = backupCfg?.frequency || "off";
    try {
      await apiBackupSetConfig(dir, freq);
      refreshBackup();
      toast.success(t('settingsBackup.dirSaved'));
    } catch (e) {
      toast.error(t('settingsBackup.dirSaveError', { error: sanitizeError(e, "") }));
    }
  };

  const handleSetBackupFreq = async (frequency: string) => {
    try {
      await apiBackupSetConfig(backupCfg?.dir ?? null, frequency);
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
      await apiBackupNow(backupCfg.dir);
      refreshBackup();
      toast.success(t('settingsBackup.backupCreated'));
    } catch (e) {
      toast.error(t('settingsBackup.backupError', { error: sanitizeError(e, "") }));
    }
  };

  const handleRestore = async () => {
    const path = await openDialog({
      title: t('settingsBackup.restoreDialogTitle'),
      filters: [{ name: "Vaultisor Vault", extensions: ["vault"] }],
    });
    if (typeof path !== "string") return;
    const ok = window.confirm(t('settingsBackup.restoreConfirm'));
    if (!ok) return;
    try {
      await apiVaultRestore(path);
      toast.success(t('settingsBackup.restored'));
      setTimeout(() => window.location.reload(), 900);
    } catch (e) {
      toast.error(sanitizeError(e, t('settingsBackup.restoreError')));
    }
  };

  const [importedFile, setImportedFile] = useState<string | null>(null);
  const [importedRecordIds, setImportedRecordIds] = useState<string[]>([]);

  const handleImportCsv = async () => {
    const path = await openDialog({
      title: t('settingsBackup.importBrowserTitle'),
      filters: [{ name: "CSV Passwords", extensions: ["csv"] }],
    });
    if (typeof path !== "string") return;
    try {
      const res = await apiImportChromiumCsv(path);
      toast.success(t('settingsBackup.importSuccess', { count: res.count }));
      setImportedFile(path);
      setImportedRecordIds(res.imported_ids);
    } catch (e) {
      toast.error(sanitizeError(e, t('settingsBackup.importError', { error: "" })));
    }
  };

  const handleSecureDeleteCsv = async () => {
    if (!importedFile) return;
    try {
      await apiSecureDeleteFile(importedFile);
      toast.success(t('settingsBackup.deleteCsvSuccess'));
      setImportedFile(null);
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

      <div className="text-2xs text-white/70 mt-1">
        <strong>{t('settingsBackup.dirLabel')}</strong>{" "}
        <span className="break-all">{backupCfg?.dir || t('settingsBackup.notSelected')}</span>
      </div>
      {backupCfg?.last_backup && (
        <div className="text-2xs text-white/50">
          {t('settingsBackup.lastBackup', { time: new Date(backupCfg.last_backup).toLocaleString() })}
        </div>
      )}

      <Button variant="secondary" size="sm" fullWidth onClick={handlePickBackupDir}>
        {backupCfg?.dir ? t('settingsBackup.changeDir') : t('settingsBackup.selectDir')}
      </Button>

      <div className="grid grid-cols-3 gap-1.5 mt-1">
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
                  : "bg-white/[0.02] text-white/55 border-white/[0.06] hover:bg-white/[0.05]",
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

      <div className="border-t border-white/[0.06] my-1" />
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

      {importedFile && (
        <div className="card-flat p-3 space-y-2 border-warning/40 bg-warning/5 animate-fade-in mt-1">
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
              onClick={() => setImportedFile(null)}
            >
              {t('settingsBackup.keepCsvBtn')}
            </Button>
          </div>

          {importedRecordIds.length > 0 && (
            <div className="pt-2 border-t border-white/10">
              <Button
                variant="secondary"
                size="sm"
                fullWidth
                onClick={handleUndoImport}
              >
                {t('settingsBackup.undoImportBtn', { count: importedRecordIds.length })}
              </Button>
            </div>
          )}
        </div>
      )}

      <div className="border-t border-white/[0.06] my-1" />
      <p className="text-2xs text-white/50 leading-snug">
        <strong>{t('settingsBackup.restoreTitle')}</strong>{" "}
        <Trans i18nKey="settingsBackup.restoreDesc" components={{ code: <code /> }} />
      </p>
      <Button
        variant="secondary"
        size="sm"
        fullWidth
        onClick={handleRestore}
        leftIcon={<RefreshCw className="h-3.5 w-3.5" />}
      >
        {t('settingsBackup.restoreBtn')}
      </Button>
    </Section>
  );
}
