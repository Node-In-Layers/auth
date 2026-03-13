import {
  memoizeValueSync,
  ModelCrudsFactory,
  CrossLayerProps,
} from '@node-in-layers/core'
import {
  DataDescription,
  OrmModel,
  ToObjectResult,
  OrmModelInstance,
  PrimaryKeyType,
  OrmSearch,
  OrmSearchResult,
} from 'functional-models'
import { isAuthCrossLayerProps } from '../../core/libs/index.js'

export const create: ModelCrudsFactory = <TData extends DataDescription>(
  model
  //context,
  //options
) => {
  const _getModel = memoizeValueSync((): OrmModel<TData> => {
    if (typeof model === 'function') {
      return model()
    }
    return model
  })

  const createFunction = <IgnoreProperties extends string = ''>(
    data: Omit<TData, IgnoreProperties> | ToObjectResult<TData>,
    crossLayerProps?: CrossLayerProps
  ): Promise<OrmModelInstance<TData>> => {
    if (!isAuthCrossLayerProps(crossLayerProps)) {
      throw new Error('Cross layer props are required')
    }
    throw new Error('Not implemented')
  }

  const retrieveFunction = (
    primaryKey: PrimaryKeyType,
    crossLayerProps?: CrossLayerProps
  ): Promise<OrmModelInstance<TData> | undefined> => {
    if (!isAuthCrossLayerProps(crossLayerProps)) {
      throw new Error('Cross layer props are required')
    }
    throw new Error('Not implemented')
  }

  const searchFunction = (
    ormSearch: OrmSearch,
    crossLayerProps?: CrossLayerProps
  ): Promise<OrmSearchResult<TData>> => {
    if (!isAuthCrossLayerProps(crossLayerProps)) {
      throw new Error('Cross layer props are required')
    }
    throw new Error('Not implemented')
  }

  const bulkInsertFunction = async (
    data: readonly TData[],
    crossLayerProps?: CrossLayerProps
  ): Promise<void> => {
    if (!isAuthCrossLayerProps(crossLayerProps)) {
      throw new Error('Cross layer props are required')
    }
    throw new Error('Not implemented')
  }

  const bulkDeleteFunction = async (
    primaryKeys: readonly PrimaryKeyType[],
    crossLayerProps?: CrossLayerProps
  ): Promise<void> => {
    if (!isAuthCrossLayerProps(crossLayerProps)) {
      throw new Error('Cross layer props are required')
    }
    throw new Error('Not implemented')
  }

  const updateFunction = (
    primaryKey: PrimaryKeyType,
    data: TData | ToObjectResult<TData>,
    crossLayerProps?: CrossLayerProps
  ): Promise<OrmModelInstance<TData>> => {
    if (!isAuthCrossLayerProps(crossLayerProps)) {
      throw new Error('Cross layer props are required')
    }
    throw new Error('Not implemented')
  }

  const deleteFunction = async (
    primaryKey: PrimaryKeyType,
    crossLayerProps?: CrossLayerProps
  ): Promise<void> => {
    if (!isAuthCrossLayerProps(crossLayerProps)) {
      throw new Error('Cross layer props are required')
    }
    throw new Error('Not implemented')
  }

  return {
    getModel: _getModel,
    create: createFunction,
    retrieve: retrieveFunction,
    update: updateFunction,
    delete: deleteFunction,
    search: searchFunction,
    bulkInsert: bulkInsertFunction,
    bulkDelete: bulkDeleteFunction,
  }
}
