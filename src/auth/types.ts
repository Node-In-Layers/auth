import { AuthNamespace, AuthenticationMethod } from '../types.js'

export type AuthServices = Readonly<{
  AuthenticationMethod 
}>

export type AuthServicesLayer = Readonly<{
  [AuthNamespace]: AuthServices
}>

export type AuthFeatures = Readonly<object>

export type AuthFeaturesLayer = Readonly<{
  [AuthNamespace]: AuthFeatures
}>

export type User = Readonly<{
  id: string,
  createdAt?: string
  updatedAt?: string
}>

export type Organization = Readonly<{
  id: string,
  createdAt?: string
  updatedAt?: string
}>

export type Role = Readonly<{
  id: string,
  createdAt?: string
  updatedAt?: string
}>
