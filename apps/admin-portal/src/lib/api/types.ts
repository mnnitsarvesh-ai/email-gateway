import type { OperationId } from './operations.gen';
import type { operations as SchemaOperations, paths } from './schema.gen';

export type { paths, components } from './schema.gen';
export type { OperationId } from './operations.gen';

type Op<Id extends OperationId> = SchemaOperations[Id];
type Responses<Id extends OperationId> = Op<Id> extends { responses: infer R } ? R : never;
type JsonOf<R> = R extends { content: { 'application/json': infer B } } ? B : never;

/** Body of the success response (200, 201 or 202) of an operation. */
export type SuccessBody<Id extends OperationId> = {
  [S in keyof Responses<Id>]: S extends 200 | 201 | 202 ? JsonOf<Responses<Id>[S]> : never;
}[keyof Responses<Id>];

/** JSON request body of an operation (`never` when it takes none). */
export type RequestBody<Id extends OperationId> =
  Op<Id> extends { requestBody?: infer B } ? JsonOf<NonNullable<B>> : never;

/** Query parameters of an operation. */
export type QueryParams<Id extends OperationId> =
  Op<Id> extends { parameters: { query?: infer Q } } ? NonNullable<Q> : never;

/** Path parameters of an operation. */
export type PathParams<Id extends OperationId> =
  Op<Id> extends { parameters: { path?: infer P } } ? NonNullable<P> : never;

/** Item type of a list operation (`data` or `items`). */
export type ListItem<Id extends OperationId> =
  SuccessBody<Id> extends { data: (infer T)[] }
    ? T
    : SuccessBody<Id> extends { items: (infer T)[] }
      ? T
      : never;

export type ApiPaths = paths;

/** `GET /auth/me` (permissions source, P11). */
export type Me = SuccessBody<'AuthController_me_v1'>;
