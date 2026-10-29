/** Small DOM helpers shared by the XML-based parsers. */

/** Parse XML text, returning `null` when the document is not well-formed. */
export function parseXml(text: string): Document | null {
  const doc = new DOMParser().parseFromString(text, 'text/xml')
  if (doc.getElementsByTagName('parsererror').length > 0) return null
  return doc
}

/** Trimmed text content of an element, or an empty string. */
export function textOf(el: Element | null | undefined): string {
  return el?.textContent?.trim() ?? ''
}

/** Direct children of `parent` with the given tag name. */
export function childrenByTag(parent: Element, tag: string): Element[] {
  return Array.from(parent.children).filter(child => child.tagName === tag)
}
