'use client';

import type { UseQueryResult } from '@tanstack/react-query';
import { useMemo } from 'react';
import type { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { CatalogShapeError, toBuilderCatalog, type BuilderCatalog } from './builder';

/** The catalogue is stable per deployment: cached 5 minutes (design §6 tenant budget). */
export const CATALOG_STALE_MS = 300_000;

export interface BuilderCatalogState {
  /** The builder's view of the catalogue (`null` while loading, on error or a shape error). */
  readonly catalog: BuilderCatalog | null;
  /** The catalogue response does not have the shape the builder needs (rendered as an error). */
  readonly shapeError: CatalogShapeError | null;
  readonly query: UseQueryResult<SuccessBody<'PolicyToolsController_catalog_v1'>, ApiError>;
}

/**
 * `GET /policies/catalog` adapted with `toBuilderCatalog` (design B1, §4.7): the only source of
 * fields, operators, value shapes, actions, parameters and limits the builder renders.
 */
export function useBuilderCatalog(): BuilderCatalogState {
  const query = useApiQuery('PolicyToolsController_catalog_v1', undefined, {
    staleTime: CATALOG_STALE_MS,
  });
  const adapted = useMemo(() => {
    if (!query.data) return { catalog: null, shapeError: null };
    try {
      return { catalog: toBuilderCatalog(query.data), shapeError: null };
    } catch (error) {
      if (error instanceof CatalogShapeError) return { catalog: null, shapeError: error };
      throw error;
    }
  }, [query.data]);
  return { ...adapted, query };
}
