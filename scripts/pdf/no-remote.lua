-- no-remote.lua — the pandoc filter scripts/report-to-pdf.sh renders every report with. A report quotes
-- the audited code, its history and on-chain data, so none of its text may reach the network, the file
-- system or the TeX engine as anything but text:
--   * an image becomes its alt text, so no file or URL is read for it;
--   * a raw block or raw inline, in any format (TeX, HTML or another), is dropped, except raw HTML that
--     runs across a blank line, which prints as text: an unclosed "<!--" in quoted text runs to the
--     next "-->", findings and all. A comment whose "<!--" and "-->" stand on lines of their own, as the
--     report templates' long comments do, still drops;
--   * math becomes inline code holding its source, since pandoc hands math to the engine as TeX;
--   * every element keeps its identifier and classes but no key=value attribute.
-- Pandoc applies these to the metadata as well as to the body. Written for pandoc 2.15 and later, the
-- versions with --sandbox, which report-to-pdf.sh requires.

function Image(el)
  return el.caption
end

-- spans_blank(t): t holds a blank line, so pandoc read it across a paragraph break.
local function spans_blank(t)
  return t:find("\n[ \t]*\n") ~= nil
end

-- lone_comment(t): t is one HTML comment whose "<!--" and "-->" each stand on a line of their own.
local function lone_comment(t)
  local body = t:match("^[ \t]*<!%-%-[ \t]*\n(.*)\n[ \t]*%-%->[ \t]*$")
  return body ~= nil and not body:find("<!--", 1, true) and not body:find("-->", 1, true)
end

-- words(s): s as plain text, each run of white space one space.
local function words(s)
  local inlines = {}
  for w in s:gmatch("%S+") do
    if #inlines > 0 then inlines[#inlines + 1] = pandoc.Space() end
    inlines[#inlines + 1] = pandoc.Str(w)
  end
  return inlines
end

function RawBlock(el)
  if el.format == "html" and spans_blank(el.text) and not lone_comment(el.text) then
    local paras = {}
    for p in (el.text .. "\n\n"):gmatch("(.-)\n[ \t]*\n") do
      if p:find("%S") then paras[#paras + 1] = pandoc.Para(words(p)) end
    end
    return paras
  end
  return {}
end

function RawInline(el)
  if el.format == "html" and spans_blank(el.text) then
    return words(el.text)
  end
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
