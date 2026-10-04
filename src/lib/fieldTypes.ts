// R-06: единый источник меток и списка типов полей (раньше дублировалось между
// RecordEdit и FieldRow).
import type { FieldType } from "./api";
import i18n from '@/lib/i18n';

export const fieldTypeLabels: Record<FieldType, string> = {
  get secret() { return i18n.t('fieldTypes.secret'); },
  get api() { return i18n.t('fieldTypes.api'); },
  get key() { return i18n.t('fieldTypes.key'); },
  get id() { return i18n.t('fieldTypes.id'); },
  get comment() { return i18n.t('fieldTypes.comment'); },
  get custom() { return i18n.t('fieldTypes.custom'); },
};

export const allFieldTypes: FieldType[] = [
  "secret",
  "api",
  "key",
  "id",
  "comment",
  "custom",
];
