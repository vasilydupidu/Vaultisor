import { useCallback, useEffect, useRef, useState } from "react";
import { apiRecordList, apiRecordReorder, type RecordModel } from "@/lib/api";

const PAGE = 60;

export type Category = "all" | "work" | "personal";

/**
 * R-01/R-04/R-05/R-03: данные списка записей.
 *  - поиск с дебаунсом (200мс);
 *  - фильтр категории — на сервере (SQL), не на клиенте;
 *  - пагинация «Показать ещё» (limit/offset), потолок 1000 снят;
 *  - отмена устаревших запросов через счётчик поколений (gen), чтобы поздний
 *    ответ не перезаписал свежий (R-04 — раньше было два источника загрузки);
 *  - reorder оптимистично + персист в зашифрованный vault (R-03).
 */
export function useRecordList(
  dbType: "records" | "web",
  category: Category,
  onError: (msg: string) => void,
) {
  const [records, setRecords] = useState<RecordModel[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(false);

  const genRef = useRef(0);
  const offsetRef = useRef(0);
  // onError держим в ref, чтобы его идентичность не попадала в deps loadFirst
  // (иначе нестабильный колбэк вызвал бы цикл перезагрузки через debounce-эффект).
  const onErrorRef = useRef(onError);
  useEffect(() => {
    onErrorRef.current = onError;
  }, [onError]);

  const loadFirst = useCallback(
    async (q: string) => {
      const gen = ++genRef.current;
      offsetRef.current = 0;
      setLoading(true);
      try {
        const list = await apiRecordList(dbType, {
          query: q,
          category,
          limit: PAGE,
          offset: 0,
        });
        if (gen !== genRef.current) return; // устаревший ответ
        setRecords(list);
        setHasMore(list.length === PAGE);
        offsetRef.current = list.length;
      } catch (e) {
        if (gen !== genRef.current) return;
        setRecords([]);
        onErrorRef.current(typeof e === "string" ? e : "Не удалось загрузить записи");
      } finally {
        if (gen === genRef.current) setLoading(false);
      }
    },
    [dbType, category],
  );

  const loadMore = useCallback(async () => {
    if (loadingMore || !hasMore) return;
    const gen = genRef.current;
    setLoadingMore(true);
    try {
      const more = await apiRecordList(dbType, {
        query,
        category,
        limit: PAGE,
        offset: offsetRef.current,
      });
      if (gen !== genRef.current) return;
      setRecords((cur) => [...cur, ...more]);
      setHasMore(more.length === PAGE);
      offsetRef.current += more.length;
    } catch {
      // молча — «Показать ещё» можно повторить
    } finally {
      if (gen === genRef.current) setLoadingMore(false);
    }
  }, [dbType, query, category, hasMore, loadingMore]);

  // Единственный источник загрузки первой страницы: дебаунс по query, а смена
  // dbType/category меняет идентичность loadFirst → эффект перезапускается.
  useEffect(() => {
    const t = setTimeout(() => loadFirst(query), 200);
    return () => clearTimeout(t);
  }, [query, loadFirst]);

  const refresh = useCallback(() => loadFirst(query), [loadFirst, query]);

  /** Применить новый порядок id к загруженным записям (оптимистично) + персист. */
  const applyOrder = useCallback(
    (orderedIds: string[]) => {
      setRecords((cur) => {
        const map = new Map(cur.map((r) => [r.id, r]));
        const next = orderedIds
          .map((id) => map.get(id))
          .filter((r): r is RecordModel => !!r);
        return next.length === cur.length ? next : cur;
      });
      apiRecordReorder(dbType, orderedIds).catch(() => refresh());
    },
    [dbType, refresh],
  );

  return {
    records,
    setRecords,
    query,
    setQuery,
    loading,
    loadingMore,
    hasMore,
    loadMore,
    refresh,
    applyOrder,
  };
}
