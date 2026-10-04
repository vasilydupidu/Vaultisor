import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { useEffect } from "react";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
  initReactI18next: { type: "3rdParty", init: () => {} },
}));

import { SecurityConfirmProvider, isAuthCancelled, useSecurityConfirm } from "./SecurityConfirm";

/** Потребитель, запускающий защищённое действие при монтировании. */
function Runner({
  run,
  onDone,
}: {
  run: () => Promise<string>;
  onDone: (outcome: string) => void;
}) {
  const authorized = useSecurityConfirm();
  useEffect(() => {
    authorized("change_pin", run)
      .then(onDone)
      .catch((e) => onDone(isAuthCancelled(e) ? "cancelled" : `error:${String(e)}`));
  }, [authorized, run, onDone]);
  return null;
}

describe("подтверждение действий безопасности", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("без AUTH_REQUIRED действие выполняется без диалога", async () => {
    const run = vi.fn().mockResolvedValue("ok");
    const onDone = vi.fn();
    render(
      <SecurityConfirmProvider>
        <Runner run={run} onDone={onDone} />
      </SecurityConfirmProvider>,
    );
    await act(async () => {});
    expect(onDone).toHaveBeenCalledWith("ok");
    expect(invokeMock).not.toHaveBeenCalled();
    expect(screen.queryByText("securityConfirm.title")).toBeNull();
  });

  it("AUTH_REQUIRED → PIN → security_authorize → один повтор", async () => {
    const run = vi
      .fn()
      .mockRejectedValueOnce("AUTH_REQUIRED:change_pin: Подтвердите PIN")
      .mockResolvedValueOnce("ok");
    const onDone = vi.fn();
    invokeMock.mockResolvedValue(undefined);
    render(
      <SecurityConfirmProvider>
        <Runner run={run} onDone={onDone} />
      </SecurityConfirmProvider>,
    );
    await act(async () => {});
    fireEvent.change(screen.getByPlaceholderText("securityConfirm.pinPrompt"), {
      target: { value: "19472856302" },
    });
    await act(async () => {
      fireEvent.click(screen.getByText("securityConfirm.confirm"));
    });
    expect(invokeMock).toHaveBeenCalledWith("security_authorize", {
      input: { action: "change_pin", pin: "19472856302" },
    });
    expect(run).toHaveBeenCalledTimes(2);
    expect(onDone).toHaveBeenCalledWith("ok");
  });

  it("неверный PIN оставляет диалог открытым, отмена даёт AuthCancelled", async () => {
    const run = vi.fn().mockRejectedValue("AUTH_REQUIRED:change_pin: Подтвердите PIN");
    const onDone = vi.fn();
    invokeMock.mockRejectedValue("INVALID_PIN: Неверный PIN");
    render(
      <SecurityConfirmProvider>
        <Runner run={run} onDone={onDone} />
      </SecurityConfirmProvider>,
    );
    await act(async () => {});
    fireEvent.change(screen.getByPlaceholderText("securityConfirm.pinPrompt"), {
      target: { value: "1" },
    });
    await act(async () => {
      fireEvent.click(screen.getByText("securityConfirm.confirm"));
    });
    expect(screen.getByText("Неверный PIN")).toBeTruthy();
    expect(onDone).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByText("common.cancel"));
    });
    expect(onDone).toHaveBeenCalledWith("cancelled");
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("другие ошибки не открывают диалог", async () => {
    const run = vi.fn().mockRejectedValue("LOCKED: Хранилище заблокировано");
    const onDone = vi.fn();
    render(
      <SecurityConfirmProvider>
        <Runner run={run} onDone={onDone} />
      </SecurityConfirmProvider>,
    );
    await act(async () => {});
    expect(onDone).toHaveBeenCalledWith("error:LOCKED: Хранилище заблокировано");
    expect(screen.queryByText("securityConfirm.title")).toBeNull();
  });
});
