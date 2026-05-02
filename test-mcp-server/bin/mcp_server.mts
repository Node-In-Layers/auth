#!/usr/bin/env tsx

import esMain from 'es-main'
import { ArgumentParser } from 'argparse'
import * as core from '@node-in-layers/core'
import { SystemConfig } from '../src/types.js'
import { System } from '../src/system/types.js'
import { McpNamespace } from '@node-in-layers/mcp-server'
const _parseArguments = () => {
  const parser = new ArgumentParser({
    description: 'Starts the MCP server.',
  })
  parser.add_argument('environment', {
    help: 'The environment for the service.',
  })
  return parser.parse_args()
}

const startServer = async (environment: string) => {
  const context = (await core.loadSystem<SystemConfig>({
    environment,
  })) as unknown as System
  console.info(
    // @ts-ignore
    `Starting MCP server on ${context.config[McpNamespace].server.connection.port}...`
  )
  await context.mcp['@node-in-layers/mcp-server'].start(context)
}

if (esMain(import.meta)) {
  const args = _parseArguments()
  startServer(args.environment).catch((error: any) => {
    console.error('Failed to start the server:', error)
    process.exit(1)
  })
}
