// @vitest-environment jsdom
import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
  initReactI18next: { type: "3rdParty", init: () => {} },
}));

import { PinKeypad } from "./PinKeypad";
import { PIN_DIGIT_MAX } from "@/lib/pinRules";

/**
 * Регрессии AUDIT 3.1.1:
 *  - keypad слушает keydown на window и раньше перехватывал ввод из полей
 *    формы, лежащих поверх него (Sheet восстановления). Цифры долей попадали
 *    в скрытый PIN, а Enter отправлял мусор на разблокировку и сжигал попытки.
 *  - maxLen по умолчанию был 12, из-за чего PIN длиной 13–16 цифр (его
 *    разрешают и онбординг, и backend) невозможно было ввести.
 */
describe("PinKeypad", () => {
  it("принимает цифры с физической клавиатуры, когда фокус не в поле ввода", () => {
    const onChange = vi.fn();
    render(<PinKeypad value="" onChange={onChange} />);
    fireEvent.keyDown(window, { key: "7" });
    expect(onChange).toHaveBeenCalledWith("7");
  });

  it("игнорирует ввод, адресованный полю формы", () => {
    const onChange = vi.fn();
    const onSubmit = vi.fn();
    render(
      <>
        <PinKeypad value="12345678901" onChange={onChange} onSubmit={onSubmit} minLen={11} />
        <input data-testid="share" />
      </>,
    );
    const input = screen.getByTestId("share");
    fireEvent.keyDown(input, { key: "7" });
    fireEvent.keyDown(input, { key: "Backspace" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onChange).not.toHaveBeenCalled();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("игнорирует ввод в contenteditable", () => {
    const onChange = vi.fn();
    render(
      <>
        <PinKeypad value="" onChange={onChange} />
        <div data-testid="editable" contentEditable />
      </>,
    );
    const editable = screen.getByTestId("editable");
    // jsdom не выставляет isContentEditable по атрибуту — задаём явно.
    Object.defineProperty(editable, "isContentEditable", { value: true });
    fireEvent.keyDown(editable, { key: "5" });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("не реагирует, когда keypad отключён (открыт модальный Sheet)", () => {
    const onChange = vi.fn();
    const onSubmit = vi.fn();
    render(
      <PinKeypad value="12345678901" onChange={onChange} onSubmit={onSubmit} minLen={11} disabled />,
    );
    fireEvent.keyDown(window, { key: "3" });
    fireEvent.keyDown(window, { key: "Enter" });
    expect(onChange).not.toHaveBeenCalled();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("по умолчанию допускает PIN длиной PIN_DIGIT_MAX", () => {
    const onChange = vi.fn();
    const twelve = "1".repeat(PIN_DIGIT_MAX - 1);
    render(<PinKeypad value={twelve} onChange={onChange} />);
    fireEvent.keyDown(window, { key: "9" });
    expect(onChange).toHaveBeenCalledWith(`${twelve}9`);
  });

  it("не даёт превысить PIN_DIGIT_MAX", () => {
    const onChange = vi.fn();
    render(<PinKeypad value={"1".repeat(PIN_DIGIT_MAX)} onChange={onChange} />);
    fireEvent.keyDown(window, { key: "9" });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("не отправляет форму, если введено меньше minLen", () => {
    const onSubmit = vi.fn();
    render(<PinKeypad value="123" onChange={() => {}} onSubmit={onSubmit} minLen={11} />);
    fireEvent.keyDown(window, { key: "Enter" });
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
