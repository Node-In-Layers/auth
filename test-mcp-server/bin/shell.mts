#!/usr/bin/env tsx

import { randomUUID } from 'node:crypto'
import invoke from 'lodash/invoke.js'
import get from 'lodash/get.js'
import esMain from 'es-main'
import { ArgumentParser } from 'argparse'
import repl from 'repl'
import chalk from 'chalk'
import merge from 'lodash/merge.js'
import { queryBuilder } from 'functional-models'
import * as core from '@node-in-layers/core'
import { services as globalServices } from '@node-in-layers/core/globals'
import { System } from '../src/system/types.js'
import { CoreNamespace } from '@node-in-layers/core'
import { asyncMap } from 'modern-async'

const _parseArguments = () => {
  const parser = new ArgumentParser({
    description: 'Starts a shell environment into the system.',
  })
  parser.add_argument('environment', {
    help: 'The environment for the service.',
  })
  parser.add_argument('-c', '--command', {
    help: 'A dot path command to run',
  })
  parser.add_argument('-d', '--data', {
    help: 'Stringified JSON data to pass to the command',
  })
  parser.add_argument('-v', '--verbose', {
    help: 'Turns on console logging to the command line',
    action: 'store_true',
  })
  return parser.parse_args()
}

const _isModelInstance = (obj: any) => {
  return (
    obj &&
    typeof obj === 'object' &&
    'getPrimaryKey' in obj &&
    typeof obj.getPrimaryKey === 'function'
  )
}

const _isModelSearchResult = (obj: any) => {
  return obj && typeof obj === 'object' && 'instances' in obj
}

const _printModelInstance = async (obj: any) => {
  console.log(JSON.stringify(await obj.toObj(), null, 2))
}

const _printModelSearchResult = async (obj: any) => {
  const models = await asyncMap(obj.instances, async instance => {
    return await (instance as any).toObj()
  })
  console.log(JSON.stringify(models, null, 2))
}

export const systemStartup = async (environment, args) => {
  const globals = globalServices.create({
    environment,
    runtimeId: randomUUID(),
    workingDirectory: process.cwd(),
  })
  const config = await globals.loadConfig()
  const consoleLogging = args?.verbose ? true : false
  const patchedConfig = merge({}, config, {
    logging: {
      consoleLogging,
    },
    [CoreNamespace.root]: {
      logging: {
        logLevel: 'silent',
      },
    },
  })
  return core.loadSystem({
    environment,
    config: patchedConfig,
  }) as unknown as System
}

const help = objects => () => {
  console.info(chalk.white.bold(`You have access to the following objects:`))
  console.info(chalk.white.bold(`[${Object.keys(objects).join(', ')}]`))
  console.info()
  console.info(
    chalk.white.bold('You can also write "help()" to see this again.')
  )
}

export const runCommand = async (args, objects, command, data) => {
  const path = command
  const func = get(objects, path)
  if (!func) {
    console.error('Function not found')
    process.exit(1)
  }
  return Promise.resolve()
    .then(() => {
      return invoke(objects, command, data)
    })
    .catch(e => {})
    .finally(async () => {
      await delay(300)
      await objects.services['@node-in-layers/data'].cleanup().catch(() => {})
    })
}

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

const main = async () => {
  const args = _parseArguments()
  const objects = {
    ...(await systemStartup(args.environment, args)),
    queryBuilder,
  }
  process.on('SIGINT', async function () {
    await objects.services['@node-in-layers/data'].cleanup()
    process.exit()
  })
  if (args.command) {
    const result = await runCommand(
      args,
      objects,
      args.command,
      args.data ? JSON.parse(args.data) : {}
    )
    if (_isModelInstance(result)) {
      await _printModelInstance(result)
    } else if (_isModelSearchResult(result)) {
      await _printModelSearchResult(result)
    } else {
      console.info(JSON.stringify(result, null, 2))
    }
    process.exit()
    return
  }
  const context = repl.start().context
  const toUse = merge({ context: objects }, objects)
  merge(context, objects, toUse)
  console.info(chalk.blue.bold(`Welcome to the shell.`))
  console.info(chalk.blue.bold(`--------------------------------`))
  const helpFunc = help(toUse)
  helpFunc()
  context.help = helpFunc
}

if (esMain(import.meta)) {
  main()
}
