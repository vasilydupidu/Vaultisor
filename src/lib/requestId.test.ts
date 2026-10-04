import { describe, it, expect } from "vitest";
import { RetryableRequest } from "./requestId";

describe("идентификатор повторяемого запроса", () => {
  it("один на повторы того же намерения", () => {
    const request = new RetryableRequest();
    const first = request.idFor("draft-1");
    expect(request.idFor("draft-1")).toBe(first);
    expect(first).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("новый при изменении содержимого и после успеха", () => {
    const request = new RetryableRequest();
    const first = request.idFor("draft-1");
    const changed = request.idFor("draft-2");
    expect(changed).not.toBe(first);
    request.done();
    expect(request.idFor("draft-2")).not.toBe(changed);
  });
});
