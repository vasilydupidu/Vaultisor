/**
 * Идентификатор запроса для идемпотентного повтора.
 *
 * Ответ backend может потеряться уже после commit. Повтор с тем же
 * идентификатором backend распознаёт и возвращает уже сделанное, а не
 * создаёт вторую запись, вторую привязку ключа или вторую копию.
 *
 * Идентификатор живёт, пока не изменилось содержимое намерения: изменённый
 * черновик — это уже другое действие, и оно получает новый идентификатор.
 * После успеха идентификатор сбрасывается.
 */
export class RetryableRequest {
  private fingerprint: string | null = null;
  private id = "";

  /** Идентификатор для намерения с данным содержимым. */
  idFor(fingerprint: string): string {
    if (fingerprint !== this.fingerprint) {
      this.fingerprint = fingerprint;
      this.id = crypto.randomUUID();
    }
    return this.id;
  }

  /** Действие выполнено: следующее получит новый идентификатор. */
  done(): void {
    this.fingerprint = null;
  }
}
