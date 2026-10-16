import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
  initReactI18next: { type: "3rdParty", init: () => {} },
}));

const recordGet = vi.fn();
const recordReveal = vi.fn();
const recordUpdate = vi.fn();
const recordCreate = vi.fn();
vi.mock("@/lib/api", () => ({
  apiRecordGet: (...a: unknown[]) => recordGet(...a),
  apiRecordReveal: (...a: unknown[]) => recordReveal(...a),
  apiRecordUpdate: (...a: unknown[]) => recordUpdate(...a),
  apiRecordCreate: (...a: unknown[]) => recordCreate(...a),
}));

import { RecordEdit } from "./RecordEdit";
import { ToastProvider, useToast } from "@/components/ui/Toast";

function ToastTrigger() {
  const toast = useToast();
  return (
    <button type="button" onClick={() => toast.error("boom")}>
      fire-toast
    </button>
  );
}

const STORED_RECORD = {
  id: "rec-1",
  name: "Original name",
  project: "example.com",
  icon: null,
  color: null,
  category: "personal" as const,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  fields: [
    {
      id: "f-secret",
      field_type: "secret" as const,
      label: "Пароль",
      is_secret: true,
      sort_order: 0,
      value_preview: "••••••••",
      created_at: "",
      updated_at: "",
    },
  ],
};

function renderEditor() {
  const onCancel = vi.fn();
  const onSaved = vi.fn();
  const view = render(
    <ToastProvider>
      <ToastTrigger />
      <RecordEdit dbType="records" recordId="rec-1" onCancel={onCancel} onSaved={onSaved} />
    </ToastProvider>,
  );
  return { ...view, onCancel, onSaved };
}

describe("RecordEdit", () => {
  beforeEach(() => {
    recordGet.mockReset().mockResolvedValue(STORED_RECORD);
    recordReveal.mockReset().mockResolvedValue("revealed");
    recordUpdate.mockReset().mockResolvedValue(undefined);
    recordCreate.mockReset().mockResolvedValue("rec-1");
  });
  afterEach(cleanup);

  /**
   * Регрессия: объект toast-api пересоздавался на каждом
   * рендере провайдера, из-за чего загрузчик записи пересоздавался и повторно
   * перетирал несохранённый черновик пользователя — в том числе сразу после
   * сообщения об ошибке сохранения.
   */
  it("не теряет черновик при появлении тоста", async () => {
    renderEditor();
    await waitFor(() => expect(recordGet).toHaveBeenCalledTimes(1));

    const nameInput = (await screen.findByDisplayValue("Original name")) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: "Черновик пользователя" } });
    expect(nameInput.value).toBe("Черновик пользователя");

    act(() => {
      screen.getByText("fire-toast").click();
    });

    // Тост показан, но запись не перезагружена и ввод сохранён.
    await waitFor(() => expect(screen.getByText("boom")).toBeTruthy());
    expect(recordGet).toHaveBeenCalledTimes(1);
    expect((screen.getByDisplayValue("Черновик пользователя") as HTMLInputElement).value).toBe(
      "Черновик пользователя",
    );
  });

  it("загружает запись ровно один раз на одну карточку", async () => {
    const { rerender } = renderEditor();
    await waitFor(() => expect(recordGet).toHaveBeenCalledTimes(1));
    rerender(
      <ToastProvider>
        <ToastTrigger />
        <RecordEdit dbType="records" recordId="rec-1" onCancel={vi.fn()} onSaved={vi.fn()} />
      </ToastProvider>,
    );
    expect(recordGet).toHaveBeenCalledTimes(1);
  });

  /**
   * Секретные поля загружаются лениво: их значение не должно расшифровываться
   * при открытии редактора.
   */
  it("не раскрывает секретные поля при открытии", async () => {
    renderEditor();
    await waitFor(() => expect(recordGet).toHaveBeenCalledTimes(1));
    expect(recordReveal).not.toHaveBeenCalled();
  });

  it("сообщает об ошибке загрузки и закрывает редактор", async () => {
    recordGet.mockRejectedValue("STORAGE_ERROR: Ошибка хранилища");
    const { onCancel } = renderEditor();
    await waitFor(() => expect(onCancel).toHaveBeenCalled());
  });

  /**
   * Комментарий — открытая заметка: ни переключателя «секретное», ни подписи
   * поля, значение в многострочном поле. Секретное поле, переведённое в
   * комментарий, перестаёт быть секретным.
   */
  it("показывает комментарий открытой заметкой", async () => {
    recordGet.mockResolvedValue({
      ...STORED_RECORD,
      fields: [
        STORED_RECORD.fields[0],
        {
          ...STORED_RECORD.fields[0],
          id: "f-note",
          field_type: "comment" as const,
          label: "fieldTypes.comment",
          is_secret: false,
          sort_order: 1,
          value_preview: "",
        },
      ],
    });
    renderEditor();
    const note = (await screen.findByLabelText("fieldTypes.comment")) as HTMLTextAreaElement;
    expect(note.tagName).toBe("TEXTAREA");
    expect(note.value).toBe("revealed");
    // Подпись и переключатель есть только у секретного поля.
    expect(screen.getAllByText("recordEdit.fieldLabel")).toHaveLength(1);
    expect(screen.getAllByText("recordEdit.secretType")).toHaveLength(1);

    const [secretType] = screen.getAllByRole("combobox") as HTMLSelectElement[];
    fireEvent.change(secretType, { target: { value: "comment" } });
    expect(screen.queryByText("recordEdit.secretType")).toBeNull();
    expect(screen.queryByText("recordEdit.fieldLabel")).toBeNull();
  });
});
