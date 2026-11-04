-- no-remote.lua — the pandoc filter scripts/report-to-pdf.sh renders every report with. A report quotes
-- the audited code, its history and on-chain data, so none of its text may reach the network, the file
-- system or the TeX engine as anything but text:
--   * an image becomes its alt text, so no file or URL is read for it;
--   * a raw block or raw inline, in any format (TeX, HTML or another), is dropped;
--   * math becomes inline code holding its source, since pandoc hands math to the engine as TeX;
--   * every element keeps its identifier and classes but no key=value attribute.
-- Pandoc applies these to the metadata as well as to the body. Written for pandoc 2.15 and later, the
-- versions with --sandbox, which report-to-pdf.sh requires.

function Image(el)
  return el.caption
end

function RawBlock(el)
  return {}
end

function RawInline(el)
  return {}
end

function Math(el)
  return pandoc.Code(el.text)
end

-- Every element keeps its identifier and classes, never a key=value attribute: the LaTeX writer passes
-- some of those to the engine as written (a figure's latex-placement).
local function plain_attr(el)
  el.attr = pandoc.Attr(el.identifier, el.classes)
  return el
end
Figure, Div, Span, Header, CodeBlock, Code, Table, Link = plain_attr, plain_attr, plain_attr, plain_attr,
  plain_attr, plain_attr, plain_attr, plain_attr
