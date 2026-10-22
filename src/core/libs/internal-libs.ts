export const isRequestCrossLayerProps = (props: any): boolean => {
  if (typeof props !== 'object' || props === null) {
    return false
  }
  return props.requestInfo !== undefined
}
