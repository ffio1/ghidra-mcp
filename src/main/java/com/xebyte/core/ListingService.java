package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for listing and enumeration endpoints.
 * All methods are read-only and do not require transactions.
 */
@McpToolGroup(value = "listing", description = "Enumerate functions, strings, segments, imports, exports, namespaces, classes, data items")
public class ListingService {

    private final ProgramProvider programProvider;

    public ListingService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    // ========================================================================
    // Listing endpoints
    // ========================================================================

    @McpTool(path = "/list_methods", description = "List all function names with pagination", category = "listing")
    public Response getAllFunctionNames(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return Response.text(ServiceUtils.paginateList(names, offset, limit));
    }

    @McpTool(path = "/list_classes", description = "List class and namespace names with pagination", category = "listing")
    public Response getAllClassNames(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return Response.text(ServiceUtils.paginateList(sorted, offset, limit));
    }

    @McpTool(path = "/list_segments", description = "List memory blocks/segments", category = "listing")
    public Response listSegments(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/list_imports", description = "List external/imported symbols", category = "listing")
    public Response listImports(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        ExternalManager extMgr = program.getExternalManager();
        List<Map<String, Object>> all = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", symbol.getName());
            entry.put("address", symbol.getAddress().toString());
            ExternalLocation extLoc = extMgr.getExternalLocation(symbol);
            if (extLoc != null) {
                String original = extLoc.getOriginalImportedName();
                if (original != null && !original.isEmpty() && !original.equals(symbol.getName())) {
                    entry.put("original_imported_name", original);
                }
            }
            all.add(entry);
        }
        int end = Math.min(offset + limit, all.size());
        return Response.ok(offset < all.size() ? all.subList(offset, end) : List.of());
    }

    @McpTool(path = "/list_exports", description = "List exported entry points", category = "listing")
    public Response listExports(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/list_namespaces", description = "List namespace hierarchy", category = "listing")
    public Response listNamespaces(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return Response.text(ServiceUtils.paginateList(sorted, offset, limit));
    }

    @McpTool(path = "/list_data_items", description = "List defined data items", category = "listing")
    public Response listDefinedData(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    StringBuilder info = new StringBuilder();
                    String label = data.getLabel() != null ? data.getLabel() : "DAT_" + data.getAddress().toString(false);
                    info.append(label);
                    info.append(" @ ").append(data.getAddress().toString(false));

                    DataType dt = data.getDataType();
                    String typeName = (dt != null) ? dt.getName() : "undefined";
                    info.append(" [").append(typeName).append("]");

                    int length = data.getLength();
                    String sizeStr = (length == 1) ? "1 byte" : length + " bytes";
                    info.append(" (").append(sizeStr).append(")");

                    lines.add(info.toString());
                }
            }
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/list_data_items_by_xrefs", description = "List data items sorted by xref count (descending). By default returns only defined data items. `filter` and `type_filter` (each: all/defined/undefined) compose orthogonally to also include unnamed/untyped addresses — `filter=all,type_filter=all` returns the full data surface (named + DAT_*-style autogen + raw undefined-with-xrefs). `min_xrefs` (default 1) suppresses zero-xref noise on undefined items.", category = "listing")
    public Response listDataItemsByXrefs(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "format", defaultValue = "text", description = "Output format (text or json)") String format,
            @Param(value = "filter", defaultValue = "defined",
                   description = "Symbol-naming axis: `all`, `defined` (default — only named symbols, preserves legacy behavior), `undefined` (only DAT_*-style and raw unnamed addresses).") String filter,
            @Param(value = "type_filter", defaultValue = "all",
                   description = "Type-assignment axis: `all` (default), `defined` (only items with a real type), `undefined` (only items with `undefined*` types or no type).") String typeFilter,
            @Param(value = "min_xrefs", defaultValue = "1",
                   description = "When undefined items are included, only return addresses with at least this many xrefs. Default 1 suppresses padding/alignment noise; set to 0 for the firehose.") int minXrefs,
            @Param(value = "include_all_sections", defaultValue = "false",
                   description = "By default only data sections are scanned. Pass true to include every memory section.") boolean includeAllSections,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        String fSym = (filter == null || filter.isEmpty()) ? "defined" : filter.toLowerCase();
        String fType = (typeFilter == null || typeFilter.isEmpty()) ? "all" : typeFilter.toLowerCase();
        int xrefMin = Math.max(0, minXrefs);

        List<DataItemInfo> dataItems = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        SymbolTable symTable = program.getSymbolTable();
        Set<Address> emittedAddrs = new HashSet<>();

        // Pass 1: defined data items (existing behavior, with axis filters).
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!includeAllSections && !isDataBlock(block)) continue;
            DataIterator it = listing.getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (!block.contains(data.getAddress())) continue;
                Address addr = data.getAddress();

                Symbol primary = symTable.getPrimarySymbol(addr);
                String name = (primary != null) ? primary.getName() : null;
                boolean isNamed = (name != null
                        && !NamingConventions.isAutoGeneratedGlobalName(name)
                        && !ServiceUtils.isAutoGeneratedName(name));
                if ("defined".equals(fSym) && !isNamed) continue;
                if ("undefined".equals(fSym) && isNamed) continue;

                DataType dt = data.getDataType();
                String typeName = (dt != null) ? dt.getName() : "undefined";
                boolean isTyped = !typeName.startsWith("undefined");
                if ("defined".equals(fType) && !isTyped) continue;
                if ("undefined".equals(fType) && isTyped) continue;

                int xrefCount = refMgr.getReferenceCountTo(addr);
                if (!isNamed && xrefCount < xrefMin) continue;

                String label = (name != null) ? name : "DAT_" + addr.toString(false);
                dataItems.add(new DataItemInfo(addr.toString(false), label, typeName,
                        data.getLength(), xrefCount));
                emittedAddrs.add(addr);
            }
        }

        // Pass 2: raw undefined addresses with xrefs (when both axes allow undefined).
        boolean wantUnnamed = "all".equals(fSym) || "undefined".equals(fSym);
        boolean wantUntyped = "all".equals(fType) || "undefined".equals(fType);
        if (wantUnnamed && wantUntyped) {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!includeAllSections && !isDataBlock(block)) continue;
                AddressIterator refs = refMgr.getReferenceDestinationIterator(
                        new AddressSet(block.getStart(), block.getEnd()), true);
                while (refs.hasNext()) {
                    Address addr = refs.next();
                    if (emittedAddrs.contains(addr)) continue;
                    if (symTable.getPrimarySymbol(addr) != null) continue;
                    if (listing.getInstructionAt(addr) != null) continue;
                    if (functionManager.getFunctionContaining(addr) != null) continue;
                    int xrefCount = refMgr.getReferenceCountTo(addr);
                    if (xrefCount < xrefMin) continue;
                    dataItems.add(new DataItemInfo(addr.toString(false),
                            "DAT_" + addr.toString(false), "undefined", 1, xrefCount));
                    emittedAddrs.add(addr);
                }
            }
        }

        dataItems.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));

        if ("json".equalsIgnoreCase(format)) {
            return formatDataItemsAsJson(dataItems, offset, limit);
        } else {
            return formatDataItemsAsText(dataItems, offset, limit);
        }
    }

    /** Backward-compat overload preserving the pre-5.7.x signature (no
     *  filter axes, no min_xrefs). Defaults exactly match the legacy
     *  behavior — defined data only, no axis filtering. */
    public Response listDataItemsByXrefs(int offset, int limit, String format,
                                         String programName) {
        return listDataItemsByXrefs(offset, limit, format,
                "defined", "all", 1, false, programName);
    }

    @McpTool(path = "/search_functions", description = "Search functions by name pattern. Omit name_pattern to list all functions.", category = "listing")
    public Response searchFunctionsByName(
            @Param(value = "name_pattern", description = "Substring to match against function names (omit or leave empty to return all functions)", defaultValue = "") String searchTerm,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (searchTerm == null || searchTerm.isEmpty()) return Response.err("Search term is required");

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return Response.text("No functions matching '" + searchTerm + "'");
        }
        return Response.text(ServiceUtils.paginateList(matches, offset, limit));
    }

    @McpTool(path = "/list_functions", description = "List all functions (no pagination)", category = "listing")
    public Response listFunctions(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                func.getName(),
                func.getEntryPoint()));
        }

        return Response.text(result.toString());
    }

    @McpTool(path = "/list_functions_enhanced", description = "List functions with thunk/external flags as JSON", category = "listing")
    public Response listFunctionsEnhanced(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "10000") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> functions = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (count >= limit) break;

            Map<String, Object> funcItem = new LinkedHashMap<>();
            funcItem.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
            funcItem.put("name", func.getName());
            funcItem.put("isThunk", "thunk".equals(AnalysisService.classifyFunction(func, program)));
            funcItem.put("isExternal", func.isExternal());
            functions.add(funcItem);
            count++;
        }

        return Response.ok(JsonHelper.mapOf(
                "functions", functions,
                "count", count,
                "offset", offset,
                "limit", limit
        ));
    }

    @McpTool(path = "/list_calling_conventions", description = "List available calling conventions", category = "listing")
    public Response listCallingConventions(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();

            StringBuilder result = new StringBuilder();
            result.append("Available Calling Conventions (").append(available.length).append("):\n\n");

            for (ghidra.program.model.lang.PrototypeModel model : available) {
                result.append("- ").append(model.getName()).append("\n");
            }

            return Response.text(result.toString());
        } catch (Exception e) {
            return Response.err("Error listing calling conventions: " + e.getMessage());
        }
    }

    @McpTool(path = "/list_strings", description = "List defined strings with optional filter", category = "listing")
    public Response listDefinedStrings(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "filter", description = "Substring filter", defaultValue = "") String filter,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && ServiceUtils.isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (!ServiceUtils.isQualityString(value)) {
                    continue;
                }

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = ServiceUtils.escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        if (lines.isEmpty()) {
            return Response.text("No quality strings found (minimum 4 characters, 80% printable)");
        }

        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/get_function_count", description = "Get total function count", category = "listing")
    public Response getFunctionCount(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        int count = program.getFunctionManager().getFunctionCount();
        return Response.ok(JsonHelper.mapOf(
                "function_count", count,
                "program", program.getName()
        ));
    }

    @McpTool(path = "/search_strings", description = "Search strings by regex pattern.", category = "listing")
    public Response searchStrings(
            @Param(value = "search_term", description = "Regex search pattern") String query,
            @Param(value = "min_length", defaultValue = "4") int minLength,
            @Param(value = "encoding", description = "String encoding filter (omit for all encodings)", defaultValue = "") String encoding,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (query == null || query.isEmpty()) return Response.err("search_term parameter is required");

        Pattern pat;
        try {
            pat = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return Response.err("Invalid regex: " + e.getMessage());
        }

        List<Map<String, Object>> results = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data == null || !ServiceUtils.isStringData(data)) continue;
            String value = data.getValue() != null ? data.getValue().toString() : "";
            if (value.length() < minLength) continue;
            if (!pat.matcher(value).find()) continue;
            String enc = (encoding != null && !encoding.isEmpty()) ? encoding : "ascii";
            Map<String, Object> item = new LinkedHashMap<>();
            item.putAll(ServiceUtils.addressToJson(data.getAddress(), program));
            item.put("value", value);
            item.put("encoding", enc);
            results.add(item);
        }

        int total = results.size();
        int from = Math.min(offset, total);
        int to = Math.min(from + limit, total);

        return Response.ok(JsonHelper.mapOf(
                "matches", results.subList(from, to),
                "total", total,
                "offset", offset,
                "limit", limit
        ));
    }

    @McpTool(path = "/list_globals", description = "List global DATA symbols. By default returns every global in the program (named + unnamed-but-xrefed undefined addresses). `filter` and `type_filter` (each: all/defined/undefined) compose orthogonally to scope the result — e.g., `filter=named, type_filter=undefined` returns the cleanup backlog (placeholders awaiting real types). `min_xrefs` (default 1) suppresses zero-xref noise when including undefined items. Code labels (branch targets, error handlers) are still excluded — they're not data globals. Each line ends with `xrefs=N` for prioritization.", category = "listing")
    public Response listGlobals(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "filter", defaultValue = "all",
                   description = "Symbol-naming axis: `all` (default), `defined` (only named symbols), `undefined` (only unnamed addresses, e.g. DAT_*-style and raw undefined data with xrefs).") String filter,
            @Param(value = "type_filter", defaultValue = "all",
                   description = "Type-assignment axis: `all` (default), `defined` (only items with a real type), `undefined` (only items with no defined type or `undefined*` types).") String typeFilter,
            @Param(value = "min_xrefs", defaultValue = "1",
                   description = "When undefined items are included, only return addresses with at least this many xrefs. Default 1 suppresses padding/alignment noise; set to 0 for the firehose.") int minXrefs,
            @Param(value = "include_all_sections", defaultValue = "false",
                   description = "By default only data sections (.data/.rdata/.bss and similar) are scanned. Pass true to include every memory section (rare — picks up .text gaps which are usually padding).") boolean includeAllSections,
            @Param(value = "name_substring", defaultValue = "",
                   description = "Optional substring match against the symbol's display line (case-insensitive). Empty = no substring filter.") String nameSubstring,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Normalize filter axes (case-insensitive, default `all`).
        String fSym = (filter == null || filter.isEmpty()) ? "all" : filter.toLowerCase();
        String fType = (typeFilter == null || typeFilter.isEmpty()) ? "all" : typeFilter.toLowerCase();
        int xrefMin = Math.max(0, minXrefs);
        String subFilter = (nameSubstring == null) ? "" : nameSubstring.toLowerCase();

        SymbolTable symbolTable = program.getSymbolTable();
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();

        // Track addresses we've already emitted so the "include undefined
        // by walking memory blocks" pass doesn't duplicate symbols already
        // surfaced by the symbol-iterator pass.
        Set<Address> emittedAddrs = new HashSet<>();
        List<String> globals = new ArrayList<>();

        // Pass 1: iterate the global namespace, emit symbols that match
        // the filter axes (skipping code labels and functions as before).
        Namespace globalNamespace = program.getGlobalNamespace();
        SymbolIterator symbols = symbolTable.getSymbols(globalNamespace);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                continue;
            }
            Address symAddr = symbol.getAddress();
            if (symAddr == null) continue;

            // Reject code-address symbols (branch targets, error handlers).
            Data definedData = listing.getDefinedDataAt(symAddr);
            if (definedData == null) {
                if (listing.getInstructionAt(symAddr) != null) continue;
                if (functionManager.getFunctionContaining(symAddr) != null) continue;
            }

            // Section gate.
            if (!includeAllSections && !isInDataSection(program, symAddr)) {
                continue;
            }

            // Axis: is this symbol "named" (real user-given name) or "undefined"
            // (DAT_*, PTR_DAT_*, FUN_*, LAB_*, UNK_*, undefined-style auto names)?
            boolean isNamed = !NamingConventions.isAutoGeneratedGlobalName(symbol.getName())
                    && !ServiceUtils.isAutoGeneratedName(symbol.getName());
            if ("defined".equals(fSym) && !isNamed) continue;
            if ("undefined".equals(fSym) && isNamed) continue;

            // Axis: type assignment.
            boolean isTyped = (definedData != null
                    && definedData.getDataType() != null
                    && !definedData.getDataType().getName().startsWith("undefined"));
            if ("defined".equals(fType) && !isTyped) continue;
            if ("undefined".equals(fType) && isTyped) continue;

            int xrefCount = refMgr.getReferenceCountTo(symAddr);
            // Apply min_xrefs only when surfacing undefined items — the
            // user explicitly asked for the noise floor on undefined-data
            // discovery, not on already-named symbols.
            if (!isNamed && xrefCount < xrefMin) continue;

            String line = formatGlobalSymbol(symbol) + " xrefs=" + xrefCount;
            if (!subFilter.isEmpty() && !line.toLowerCase().contains(subFilter)) continue;
            globals.add(line);
            emittedAddrs.add(symAddr);
        }

        // Pass 2: when the filter axes allow undefined items, also walk
        // the data sections and surface raw undefined addresses with
        // ≥ min_xrefs that have no symbol at all (and weren't already
        // emitted by Pass 1). These are the high-value discovery
        // candidates.
        boolean wantUnnamed = "all".equals(fSym) || "undefined".equals(fSym);
        boolean wantUntyped = "all".equals(fType) || "undefined".equals(fType);
        if (wantUnnamed && wantUntyped) {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!includeAllSections && !isDataBlock(block)) continue;
                if (!block.isInitialized() && !block.isMapped()) {
                    // .bss-style uninitialized blocks ARE valid data sections;
                    // keep them. Other unmapped/special blocks are skipped.
                    if (!"bss".equalsIgnoreCase(block.getName())) continue;
                }
                Address start = block.getStart();
                Address end = block.getEnd();
                AddressIterator refs = refMgr.getReferenceDestinationIterator(
                        new AddressSet(start, end), true);
                while (refs.hasNext()) {
                    Address addr = refs.next();
                    if (emittedAddrs.contains(addr)) continue;
                    // Skip if there's a symbol — already covered by Pass 1.
                    if (symbolTable.getPrimarySymbol(addr) != null) continue;
                    // Skip code addresses.
                    if (listing.getInstructionAt(addr) != null) continue;
                    if (functionManager.getFunctionContaining(addr) != null) continue;
                    int xrefCount = refMgr.getReferenceCountTo(addr);
                    if (xrefCount < xrefMin) continue;
                    Data d = listing.getDefinedDataAt(addr);
                    String typeName = (d != null && d.getDataType() != null)
                            ? d.getDataType().getName() : "undefined";
                    int len = (d != null) ? d.getLength() : 1;
                    String line = "DAT_" + addr.toString(false)
                            + " @ " + addr.toString(false)
                            + " [Label] (" + typeName + ")"
                            + " xrefs=" + xrefCount;
                    if (!subFilter.isEmpty() && !line.toLowerCase().contains(subFilter)) continue;
                    globals.add(line);
                    emittedAddrs.add(addr);
                }
            }
        }

        return Response.text(ServiceUtils.paginateList(globals, offset, limit));
    }

    /** Backward-compat overload preserving the pre-5.7.x signature
     *  (single substring filter only). The legacy `filter` param is now
     *  the substring matcher; new callers should use the full overload
     *  to access the defined/undefined axis filters. */
    public Response listGlobals(int offset, int limit, String filter,
                                String programName) {
        return listGlobals(offset, limit,
                /* filter (axis) */ "all",
                /* type_filter */ "all",
                /* min_xrefs */ 1,
                /* include_all_sections */ false,
                /* name_substring (legacy filter param) */ filter,
                programName);
    }

    /** Whether {@code block} is a data section (.data/.rdata/.bss/etc.) — an
     *  initialized non-executable block, or the conventional .bss name. */
    private static boolean isDataBlock(MemoryBlock block) {
        if (block.isExecute()) return false;
        String name = (block.getName() == null) ? "" : block.getName().toLowerCase();
        if (name.contains(".text") || name.contains("code")) return false;
        // Data-style block: data, rdata, bss, idata (import directory),
        // .CRT, .tls, etc. Default-allow all non-executable blocks.
        return true;
    }

    /** Convenience wrapper for callers that already have an Address. */
    private static boolean isInDataSection(Program program, Address addr) {
        MemoryBlock block = program.getMemory().getBlock(addr);
        return block != null && isDataBlock(block);
    }

    @McpTool(path = "/get_entry_points", description = "Get program entry points", category = "listing")
    public Response getEntryPoints(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> entryPoints = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();

        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            if (symbol.isExternalEntryPoint()) {
                String entryInfo = formatEntryPoint(symbol) + " [external entry]";
                entryPoints.add(entryInfo);
            }
        }

        String[] commonEntryNames = {"main", "_main", "start", "_start", "WinMain", "_WinMain",
                                   "DllMain", "_DllMain", "entry", "_entry"};

        for (String entryName : commonEntryNames) {
            SymbolIterator symbols = symbolTable.getSymbols(entryName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
                    String entryInfo = formatEntryPoint(symbol) + " [common entry name]";
                    if (!containsAddress(entryPoints, symbol.getAddress())) {
                        entryPoints.add(entryInfo);
                    }
                }
            }
        }

        Address programEntry = program.getImageBase();
        if (programEntry != null) {
            Symbol entrySymbol = symbolTable.getPrimarySymbol(programEntry);
            String entryInfo;
            if (entrySymbol != null) {
                entryInfo = formatEntryPoint(entrySymbol) + " [program entry]";
            } else {
                entryInfo = "entry @ " + programEntry + " [program entry] [FUNCTION]";
            }
            if (!containsAddress(entryPoints, programEntry)) {
                entryPoints.add(entryInfo);
            }
        }

        if (entryPoints.isEmpty()) {
            String[] commonHexAddresses = {"0x401000", "0x400000", "0x1000", "0x10000"};
            for (String hexAddr : commonHexAddresses) {
                try {
                    Address addr = ServiceUtils.parseAddress(program, hexAddr);
                    if (addr != null && program.getMemory().contains(addr)) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            entryPoints.add("entry @ " + addr + " (" + func.getName() + ") [potential entry] [FUNCTION]");
                        }
                    }
                } catch (Exception e) {
                    // Ignore invalid addresses
                }
            }
        }

        if (entryPoints.isEmpty()) {
            return Response.text("No entry points found in program");
        }

        return Response.text(String.join("\n", entryPoints));
    }

    // ========================================================================
    // Inner classes and helpers
    // ========================================================================

    static class DataItemInfo {
        final String address;
        final String label;
        final String typeName;
        final int length;
        final int xrefCount;

        DataItemInfo(String address, String label, String typeName, int length, int xrefCount) {
            this.address = address;
            this.label = label;
            this.typeName = typeName;
            this.length = length;
            this.xrefCount = xrefCount;
        }
    }

    private Response formatDataItemsAsText(List<DataItemInfo> dataItems, int offset, int limit) {
        List<String> lines = new ArrayList<>();

        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());

        for (int i = start; i < end; i++) {
            DataItemInfo item = dataItems.get(i);

            StringBuilder line = new StringBuilder();
            line.append(item.label);
            line.append(" @ ").append(item.address);
            line.append(" [").append(item.typeName).append("]");

            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            line.append(" (").append(sizeStr).append(")");
            line.append(" - ").append(item.xrefCount).append(" xrefs");

            lines.add(line.toString());
        }

        return Response.text(String.join("\n", lines));
    }

    private Response formatDataItemsAsJson(List<DataItemInfo> dataItems, int offset, int limit) {
        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());

        List<Map<String, Object>> items = new ArrayList<>();
        for (int i = start; i < end; i++) {
            DataItemInfo item = dataItems.get(i);
            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            items.add(JsonHelper.mapOf(
                    "address", item.address,
                    "name", item.label,
                    "type", item.typeName,
                    "size", sizeStr,
                    "xref_count", item.xrefCount
            ));
        }

        return Response.ok(items);
    }

    private String formatGlobalSymbol(Symbol symbol) {
        StringBuilder info = new StringBuilder();
        info.append(symbol.getName());
        info.append(" @ ").append(symbol.getAddress());
        info.append(" [").append(symbol.getSymbolType()).append("]");

        if (symbol.getObject() instanceof Data) {
            Data data = (Data) symbol.getObject();
            DataType dt = data.getDataType();
            if (dt != null) {
                info.append(" (").append(dt.getName()).append(")");
            }
        }

        return info.toString();
    }

    private String formatEntryPoint(Symbol symbol) {
        StringBuilder info = new StringBuilder();
        info.append(symbol.getName());
        info.append(" @ ").append(symbol.getAddress());
        info.append(" [").append(symbol.getSymbolType()).append("]");

        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            Function func = (Function) symbol.getObject();
            if (func != null) {
                info.append(" (").append(func.getParameterCount()).append(" params)");
            }
        }

        return info.toString();
    }

    private boolean containsAddress(List<String> entryPoints, Address address) {
        String addrStr = address.toString();
        for (String entry : entryPoints) {
            if (entry.contains("@ " + addrStr)) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // External Location Listing
    // ========================================================================

    @McpTool(path = "/list_external_locations", description = "List external symbol locations", category = "listing")
    public Response listExternalLocations(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        ExternalManager extMgr = program.getExternalManager();

        try {
            List<Map<String, Object>> results = new ArrayList<>();
            String[] extLibNames = extMgr.getExternalLibraryNames();
            for (String libName : extLibNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("name", extLoc.getLabel());
                    entry.put("library", libName);
                    entry.put("address", extLoc.getAddress().toString(false));
                    String original = extLoc.getOriginalImportedName();
                    if (original != null && !original.isEmpty() && !original.equals(extLoc.getLabel())) {
                        entry.put("original_imported_name", original);
                    }
                    results.add(entry);
                }
            }
            int end = Math.min(offset + limit, results.size());
            return Response.ok(offset < results.size() ? results.subList(offset, end) : List.of());
        } catch (Exception e) {
            Msg.error(this, "Error listing external locations: " + e.getMessage());
            return Response.err(e.getMessage());
        }
    }

    public Response listExternalLocations(int offset, int limit) {
        return listExternalLocations(offset, limit, null);
    }

    @McpTool(path = "/get_external_location", description = "Get external location details by address or DLL name", category = "listing")
    public Response getExternalLocationDetails(
            @Param(value = "address") String address,
            @Param(value = "dll_name") String dllName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address addr = ServiceUtils.parseAddress(program, address);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());
        ExternalManager extMgr = program.getExternalManager();

        if (dllName != null && !dllName.isEmpty()) {
            ExternalLocationIterator iter = extMgr.getExternalLocations(dllName);
            while (iter.hasNext()) {
                ExternalLocation extLoc = iter.next();
                if (extLoc.getAddress().equals(addr)) {
                    return Response.ok(externalLocationToMap(extLoc, dllName));
                }
            }
            return Response.err("External location not found in DLL");
        } else {
            String[] libNames = extMgr.getExternalLibraryNames();
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        return Response.ok(externalLocationToMap(extLoc, libName));
                    }
                }
            }
            return Response.ok(JsonHelper.mapOf("address", address));
        }
    }

    public Response getExternalLocationDetails(String address, String dllName) {
        return getExternalLocationDetails(address, dllName, null);
    }

    private static Map<String, Object> externalLocationToMap(ExternalLocation extLoc, String libName) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("address", extLoc.getAddress().toString());
        entry.put("dll_name", libName);
        entry.put("label", extLoc.getLabel());
        String original = extLoc.getOriginalImportedName();
        if (original != null && !original.isEmpty() && !original.equals(extLoc.getLabel())) {
            entry.put("original_imported_name", original);
        }
        return entry;
    }

    // ======================================================================
    // Utility endpoints (not program-scoped)
    // ======================================================================

    @McpTool(path = "/convert_number", description = "Convert number between hex/decimal/binary formats", category = "listing")
    public Response convertNumber(
            @Param(value = "text", description = "Number to convert") String text,
            @Param(value = "size", defaultValue = "4", description = "Size in bytes") int size) {
        return Response.text(ServiceUtils.convertNumber(text, size));
    }

    // ======================================================================
    // Range-scoped + vtable + string-anchored helpers (custom extensions)
    // ======================================================================

    /**
     * Parse a comma-separated name_filter into a trimmed array. Returns empty array
     * for null or empty input (no filtering).
     */
    private static String[] parseNameFilter(String nameFilter) {
        if (nameFilter == null || nameFilter.isEmpty()) return new String[0];
        String[] prefixes = nameFilter.split(",");
        int n = 0;
        for (int i = 0; i < prefixes.length; i++) {
            String trimmed = prefixes[i].trim();
            if (!trimmed.isEmpty()) prefixes[n++] = trimmed;
        }
        if (n == prefixes.length) return prefixes;
        String[] out = new String[n];
        System.arraycopy(prefixes, 0, out, 0, n);
        return out;
    }

    /**
     * Check whether a function matches any of the given name prefixes.
     * Matching is case-insensitive and checks both the simple name and the
     * fully-qualified (namespace-prefixed) name.
     */
    private static boolean matchesNameFilter(Function func, String[] prefixes) {
        if (prefixes.length == 0) return true;
        String simpleName = func.getName();
        String qualName = func.getName(true);
        String simpleLower = simpleName.toLowerCase();
        String qualLower = qualName.toLowerCase();
        for (String prefix : prefixes) {
            String p = prefix.toLowerCase();
            if (simpleLower.startsWith(p) || qualLower.startsWith(p)) return true;
        }
        return false;
    }

    @McpTool(path = "/list_functions_in_range", description = "List functions whose entry point falls within [start_address, end_address). Much faster than list_functions for agents working a specific address range.", category = "listing")
    public Response listFunctionsInRange(
            @Param(value = "start_address", description = "Start of range, inclusive (hex, e.g. \"00cc0000\")") String startAddr,
            @Param(value = "end_address", description = "End of range, exclusive (hex, e.g. \"00d00000\")") String endAddr,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "500") int limit,
            @Param(value = "name_filter", description = "Only return functions whose simple or fully-qualified name starts with this prefix (case-insensitive). Comma-separate multiple prefixes, e.g. \"FUN_,Unknown::,GRScript::Helper_\". Leave empty to return all functions.", defaultValue = "") String nameFilter,
            @Param(value = "min_size", description = "Minimum function body size in bytes (0 = no minimum)", defaultValue = "0") int minSize,
            @Param(value = "max_size", description = "Maximum function body size in bytes (0 = no maximum)", defaultValue = "0") int maxSize,
            @Param(value = "format", defaultValue = "json",
                   description = "Output format: 'json' (default, structured) or 'line' (one 'addr name size' line per result — token-efficient for iteration)") String format,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address start = ServiceUtils.parseAddress(program, startAddr);
        if (start == null) return Response.err("Invalid start_address: " + ServiceUtils.getLastParseError());

        Address end = ServiceUtils.parseAddress(program, endAddr);
        if (end == null) return Response.err("Invalid end_address: " + ServiceUtils.getLastParseError());

        String[] prefixes = parseNameFilter(nameFilter);

        List<Map<String, Object>> functions = new ArrayList<>();
        int skipped = 0;
        int added = 0;

        for (Function func : program.getFunctionManager().getFunctions(start, true)) {
            Address entry = func.getEntryPoint();
            if (entry.compareTo(end) >= 0) break;

            if (!matchesNameFilter(func, prefixes)) continue;

            long size = func.getBody().getNumAddresses();
            if (minSize > 0 && size < minSize) continue;
            if (maxSize > 0 && size > maxSize) continue;

            if (skipped < offset) { skipped++; continue; }
            if (added >= limit) break;

            Map<String, Object> item = new LinkedHashMap<>();
            item.putAll(ServiceUtils.addressToJson(entry, program));
            item.put("name", func.getName(true));
            item.put("size", size);
            functions.add(item);
            added++;
        }

        if ("line".equalsIgnoreCase(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("count=").append(added)
              .append(" offset=").append(offset)
              .append(" limit=").append(limit)
              .append(" start=").append(start.toString(false))
              .append(" end=").append(end.toString(false))
              .append('\n');
            for (Map<String, Object> item : functions) {
                sb.append(item.get("address"))
                  .append(' ').append(item.get("name"))
                  .append(' ').append(item.get("size"))
                  .append('\n');
            }
            return Response.text(sb.toString());
        }

        return Response.ok(JsonHelper.mapOf(
                "functions", functions,
                "count", added,
                "offset", offset,
                "limit", limit,
                "start_address", start.toString(false),
                "end_address", end.toString(false)
        ));
    }

    @McpTool(path = "/count_functions_in_range", description = "Count functions in an address range, optionally filtered by name prefix. Cheap probe — use before committing a full sweep.", category = "listing")
    public Response countFunctionsInRange(
            @Param(value = "start_address", description = "Start of range, inclusive (hex, e.g. \"00cc0000\")") String startAddr,
            @Param(value = "end_address", description = "End of range, exclusive (hex, e.g. \"00d00000\")") String endAddr,
            @Param(value = "name_filter", description = "Only count functions whose simple or fully-qualified name starts with this prefix (case-insensitive). Comma-separate multiple prefixes, e.g. \"FUN_,Unknown::,GRScript::Helper_\". Leave empty to count all functions in the range.", defaultValue = "") String nameFilter,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address start = ServiceUtils.parseAddress(program, startAddr);
        if (start == null) return Response.err("Invalid start_address: " + ServiceUtils.getLastParseError());

        Address end = ServiceUtils.parseAddress(program, endAddr);
        if (end == null) return Response.err("Invalid end_address: " + ServiceUtils.getLastParseError());

        String[] prefixes = parseNameFilter(nameFilter);

        int total = 0;
        int unnamed = 0;

        for (Function func : program.getFunctionManager().getFunctions(start, true)) {
            if (func.getEntryPoint().compareTo(end) >= 0) break;
            if (!matchesNameFilter(func, prefixes)) continue;
            total++;
            if (func.getName().startsWith("FUN_")) unnamed++;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("count", total);
        result.put("start_address", start.toString(false));
        result.put("end_address", end.toString(false));
        if (prefixes.length > 0) result.put("name_filter", nameFilter);
        else result.put("unnamed_count", unnamed);

        return Response.ok(result);
    }

    @McpTool(path = "/get_vtable_at", description = "Read a vtable at the given address: returns slot index, pointer value, and current function name for each entry. Useful for mapping class virtual method tables in 32-bit and 64-bit binaries.", category = "listing")
    public Response getVtableAt(
            @Param(value = "address", description = "Address of the vtable (hex)") String addressStr,
            @Param(value = "slot_count", description = "Number of vtable slots to read", defaultValue = "32") int slotCount,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address vtableAddr = ServiceUtils.parseAddress(program, addressStr);
        if (vtableAddr == null) return Response.err("Invalid address: " + ServiceUtils.getLastParseError());

        int ptrSize = program.getDefaultPointerSize();
        if (ptrSize != 4 && ptrSize != 8) return Response.err("Unsupported pointer size: " + ptrSize);

        ghidra.program.model.mem.Memory memory = program.getMemory();
        FunctionManager funcMgr = program.getFunctionManager();

        List<Map<String, Object>> slots = new ArrayList<>();
        for (int i = 0; i < slotCount; i++) {
            try {
                Address slotAddr = vtableAddr.add((long) i * ptrSize);
                long fnPtr;
                if (ptrSize == 4) {
                    fnPtr = memory.getInt(slotAddr) & 0xFFFFFFFFL;
                } else {
                    fnPtr = memory.getLong(slotAddr);
                }
                Address fnAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(fnPtr);
                Function fn = funcMgr.getFunctionAt(fnAddr);
                Map<String, Object> slot = new LinkedHashMap<>();
                slot.put("slot", i);
                slot.put("pointer", String.format("%08x", fnPtr));
                slot.put("name", fn != null ? fn.getName(true) : "(no function)");
                slots.add(slot);
            } catch (Exception e) {
                // Hit unmapped memory — vtable ends here
                break;
            }
        }

        return Response.ok(JsonHelper.mapOf(
                "vtable_address", vtableAddr.toString(false),
                "slots_read", slots.size(),
                "ptr_size", ptrSize,
                "slots", slots
        ));
    }

    @McpTool(path = "/get_call_site_constants", description = "For a function, extract each CALL site's constant-argument fingerprint: the callee (direct target name, an indirect vtable 'slot:0xNN', or 'reg:NAME'), and the forwarded x86-32 PUSH-chain arguments as signed integer constants or placeholders ('reg:NAME'/'mem'). The constant vector is a compiler-invariant fingerprint that disambiguates sibling wrappers across the clang/MSVC gap (e.g. operator new forwards 1,0,-1,0 with hint|0x400 vs _Malloc 5,0,-1,0). Pair with the Mac build to recover a misnamed wrapper's real name (see /re-id-function). Read-only.", category = "listing")
    public Response getCallSiteConstants(
            @Param(value = "function_address", description = "Address within the target function (hex)") String addressStr,
            @Param(value = "max_args", description = "Max PUSH args to capture per call site", defaultValue = "12") int maxArgs,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err("Invalid address: " + ServiceUtils.getLastParseError());
        FunctionManager funcMgr = program.getFunctionManager();
        Function fn = funcMgr.getFunctionContaining(addr);
        if (fn == null) return Response.err("No function containing " + addressStr);

        Listing listing = program.getListing();
        List<Instruction> insns = new ArrayList<>();
        InstructionIterator iit = listing.getInstructions(fn.getBody(), true);
        while (iit.hasNext()) insns.add(iit.next());

        List<Map<String, Object>> sites = extractCallSites(funcMgr, insns, maxArgs);

        return Response.ok(JsonHelper.mapOf(
                "function", fn.getName(true),
                "entry", fn.getEntryPoint().toString(false),
                "call_sites", sites
        ));
    }

    /**
     * Shared call-site extraction used by {@code get_call_site_constants} and
     * {@code get_function_fingerprint}. For each CALL in {@code insns}, resolves the callee
     * (direct name / vtable "slot:0xNN via REG" / "reg:NAME") and walks the preceding PUSH
     * chain to recover the forwarded constant-argument vector. The returned per-site maps
     * carry {@code address}, {@code kind}, {@code callee}, {@code const_vector}, and {@code args}.
     * Compiler-invariant fingerprint logic — keep identical to the inlined original.
     */
    private List<Map<String, Object>> extractCallSites(FunctionManager funcMgr,
            List<Instruction> insns, int maxArgs) {
        List<Map<String, Object>> sites = new ArrayList<>();
        for (int i = 0; i < insns.size(); i++) {
            Instruction call = insns.get(i);
            if (!"CALL".equalsIgnoreCase(call.getMnemonicString())) continue;

            // resolve callee
            String kind, callee;
            int ot0 = call.getNumOperands() > 0 ? call.getOperandType(0) : 0;
            Address tgt = null;
            for (Reference r : call.getReferencesFrom()) {
                if (r.getReferenceType().isCall()) { tgt = r.getToAddress(); break; }
            }
            if ((ot0 & OperandType.DYNAMIC) != 0) {
                long disp = 0; String base = null;
                for (Object o : call.getOpObjects(0)) {
                    if (o instanceof Scalar) disp = ((Scalar) o).getValue();
                    else if (o instanceof Register) base = ((Register) o).getName();
                }
                kind = "vtable-slot";
                callee = "slot:0x" + Long.toHexString(disp) + (base != null ? " via " + base : "");
            } else if (tgt != null) {
                Function tf = funcMgr.getFunctionAt(tgt);
                kind = "direct";
                callee = tf != null ? tf.getName(true) : tgt.toString(false);
            } else if ((ot0 & OperandType.REGISTER) != 0) {
                String base = null;
                for (Object o : call.getOpObjects(0)) if (o instanceof Register) base = ((Register) o).getName();
                // Backtrace the call register: `CALL EDX` where EDX <- MOV EDX,[ECX+disp]
                // is a virtual dispatch through vtable slot 0xdisp. Recover it.
                String resolved = resolveReg(insns, i, base, 5);
                Matcher mm = MEM_PAT.matcher(resolved);
                if (mm.matches()) {
                    String viaReg = mm.group(1);
                    long disp = mm.group(2) == null ? 0 : Long.parseLong(mm.group(2), 16);
                    kind = "vtable-slot";
                    callee = "slot:0x" + Long.toHexString(disp) + " via " + viaReg;
                } else {
                    kind = "indirect-reg";
                    callee = resolved.startsWith("reg:") ? resolved : "reg:" + base + " (" + resolved + ")";
                }
            } else {
                kind = "unknown";
                callee = call.getNumOperands() > 0 ? call.getDefaultOperandRepresentation(0) : "?";
            }

            // walk back collecting PUSH args until the previous CALL (PUSH is right-to-left)
            List<String> args = new ArrayList<>();
            List<String> consts = new ArrayList<>();
            for (int j = i - 1; j >= 0 && args.size() < maxArgs; j--) {
                Instruction p = insns.get(j);
                String pm = p.getMnemonicString();
                if ("CALL".equalsIgnoreCase(pm)) break;
                if (!"PUSH".equalsIgnoreCase(pm)) continue;
                int pt = p.getNumOperands() > 0 ? p.getOperandType(0) : 0;
                if ((pt & OperandType.SCALAR) != 0 && (pt & OperandType.DYNAMIC) == 0) {
                    Scalar sc = null;
                    for (Object o : p.getOpObjects(0)) if (o instanceof Scalar) sc = (Scalar) o;
                    String v = sc != null ? Long.toString(sc.getSignedValue()) : "?";
                    args.add(v); consts.add(v);
                } else if ((pt & OperandType.REGISTER) != 0 && (pt & OperandType.DYNAMIC) == 0) {
                    String rn = null;
                    for (Object o : p.getOpObjects(0)) if (o instanceof Register) rn = ((Register) o).getName();
                    // Backtrace the pushed register to its symbolic source:
                    // LEA -> &[mem], MOV-from-mem -> [mem] (+ folded |0xN hint), MOV-imm -> scalar.
                    args.add(resolveReg(insns, j, rn, 6));
                } else if ((pt & OperandType.DYNAMIC) != 0) {
                    String mr = opMem(p, 0);
                    args.add(mr + scanImmArith(insns, j, mr));
                } else {
                    args.add("mem");
                }
            }
            // walk was right-to-left (nearest-the-call PUSH = arg1), so the lists are
            // already in C-argument order (arg1 first) — matches the documented
            // operator-new fingerprint 1,0,-1,0. Do NOT reverse.

            Map<String, Object> site = new LinkedHashMap<>();
            site.put("address", call.getAddress().toString(false));
            site.put("kind", kind);
            site.put("callee", callee);
            site.put("const_vector", String.join(",", consts));
            site.put("args", args);
            sites.add(site);
        }
        return sites;
    }

    @McpTool(path = "/get_function_fingerprint", description = "Compute a compact cross-build comparison vector for one function: {entry, name, size, retType, paramCount, callingConvention, strings (referenced literals), directCallees (named call targets), vtableSlotsCalled (indirect-call displacements like '+0xb4 via EDX'), constVectors (forwarded PUSH constant vectors per call site — same extraction as get_call_site_constants), fieldOffsets (ordered distinct this/ECX+0xNN access offsets)}. This is the shared primitive for cross-build function matching (/re-cross-twin, /re-id-function, /re-class-port). Read-only.", category = "listing")
    public Response getFunctionFingerprint(
            @Param(value = "function_address", description = "Address within the target function (hex)") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err("Invalid address: " + ServiceUtils.getLastParseError());
        FunctionManager funcMgr = program.getFunctionManager();
        Function fn = funcMgr.getFunctionContaining(addr);
        if (fn == null) return Response.err("No function containing " + addressStr);

        Listing listing = program.getListing();
        ghidra.program.model.symbol.ReferenceManager refMgr = program.getReferenceManager();

        List<Instruction> insns = new ArrayList<>();
        InstructionIterator iit = listing.getInstructions(fn.getBody(), true);
        while (iit.hasNext()) insns.add(iit.next());

        // Referenced string literals (data references whose target is string data).
        List<String> strings = new ArrayList<>();
        // Distinct this/ECX +0xNN field-access offsets, in first-seen order.
        List<String> fieldOffsets = new ArrayList<>();
        Set<String> seenOffsets = new LinkedHashSet<>();
        for (Instruction insn : insns) {
            for (Reference r : insn.getReferencesFrom()) {
                if (!r.getReferenceType().isData()) continue;
                Data d = listing.getDataAt(r.getToAddress());
                if (d != null && ServiceUtils.isStringData(d)) {
                    String v = d.getValue() != null ? d.getValue().toString() : "";
                    if (!v.isEmpty() && !strings.contains(v)) strings.add(v);
                }
            }
            // Field access through ECX/this: any operand rendered as "[ECX + 0xNN]".
            for (int op = 0; op < insn.getNumOperands(); op++) {
                if ((insn.getOperandType(op) & OperandType.DYNAMIC) == 0) continue;
                Matcher fm = FIELD_PAT.matcher(opMem(insn, op));
                if (fm.matches()) {
                    String off = "+0x" + (fm.group(1) == null ? "0" : fm.group(1).toLowerCase());
                    if (seenOffsets.add(off)) fieldOffsets.add(off);
                }
            }
        }

        // Call sites: split into named direct callees, indirect vtable-slot calls, and const vectors.
        List<Map<String, Object>> sites = extractCallSites(funcMgr, insns, 12);
        List<String> directCallees = new ArrayList<>();
        List<String> vtableSlotsCalled = new ArrayList<>();
        List<String> constVectors = new ArrayList<>();
        for (Map<String, Object> site : sites) {
            String kind = (String) site.get("kind");
            String callee = (String) site.get("callee");
            String cv = (String) site.get("const_vector");
            if (cv != null && !cv.isEmpty() && !constVectors.contains(cv)) constVectors.add(cv);
            if ("direct".equals(kind)) {
                if (callee != null && !callee.startsWith("FUN_") && !directCallees.contains(callee)) {
                    directCallees.add(callee);
                }
            } else if ("vtable-slot".equals(kind)) {
                // Normalize "slot:0x4 via EDX" -> "+0x4 via EDX" for cross-build comparison.
                String norm = callee != null ? callee.replaceFirst("^slot:0x", "+0x") : callee;
                if (norm != null && !vtableSlotsCalled.contains(norm)) vtableSlotsCalled.add(norm);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("entry", fn.getEntryPoint().toString(false));
        result.put("name", fn.getName(true));
        result.put("size", fn.getBody().getNumAddresses());
        result.put("retType", fn.getReturnType() != null ? fn.getReturnType().getDisplayName() : "undefined");
        result.put("paramCount", fn.getParameterCount());
        String cc;
        try { cc = fn.getCallingConventionName(); } catch (Exception e) { cc = null; }
        result.put("callingConvention", cc);
        result.put("strings", strings);
        result.put("directCallees", directCallees);
        result.put("vtableSlotsCalled", vtableSlotsCalled);
        result.put("constVectors", constVectors);
        result.put("fieldOffsets", fieldOffsets);
        return Response.ok(result);
    }

    // Matches "[ECX + 0xNN]" / "[ECX]" — the 'this' field-access pattern. The base register
    // (ECX/RCX/this) is non-capturing; group(1) = the hex offset (null when the access is [ECX]).
    private static final Pattern FIELD_PAT =
            Pattern.compile("\\[(?:ECX|RCX|this)(?:\\s*\\+\\s*0x([0-9a-fA-F]+))?\\]",
                    Pattern.CASE_INSENSITIVE);

    @McpTool(path = "/get_class_layout_signature", description = "Compute a class's destructor-derived LAYOUT fingerprint for cross-build layout matching: {class_name, dtorAddr, opDeleteSize (size immediate passed to operator delete / the scalar-deleting destructor), baseChain (first super-dtor call target name(s)), memberFreeOffsets (this+0xNN offsets that get a refcount-release vtable call or a buffer free in the dtor), memberCount (from the class namespace), highestMemberOffset (largest this+0xNN write seen)}. Locates the scalar-deleting / D1 destructor by name within the class namespace. Powers /re-layout-invariance (the client compares two signatures). Read-only.", category = "listing")
    public Response getClassLayoutSignature(
            @Param(value = "class_name", description = "C++ class / namespace name, e.g. 'efd::DataStore'") String className,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        if (className == null || className.trim().isEmpty()) return Response.err("class_name is required");
        final String cls = className.trim();
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        SymbolTable st = program.getSymbolTable();
        Namespace global = program.getGlobalNamespace();
        Namespace classNs = st.getNamespace(cls, global);
        if (classNs == null || classNs.isGlobal()) {
            return Response.err("No namespace named '" + cls + "'. Use list_classes to find the exact class name.");
        }

        FunctionManager funcMgr = program.getFunctionManager();
        Listing listing = program.getListing();

        // Collect the class's member functions; find the destructor (scalar-deleting / D1).
        int memberCount = 0;
        Function dtor = null;
        for (Symbol sym : st.getSymbols(classNs)) {
            Function f = funcMgr.getFunctionAt(sym.getAddress());
            if (f == null || !classNs.equals(f.getParentNamespace())) continue;
            memberCount++;
            String n = f.getName();
            // Prefer a name that looks like a destructor; tolerate Ghidra/Itanium spellings.
            if (dtor == null && isDestructorName(n, cls)) dtor = f;
        }
        if (dtor == null) {
            // Second pass: a member literally named like the class with a leading '~'.
            for (Symbol sym : st.getSymbols(classNs)) {
                Function f = funcMgr.getFunctionAt(sym.getAddress());
                if (f == null) continue;
                if (f.getName().contains("~") || f.getName().toLowerCase().contains("destructor")) { dtor = f; break; }
            }
        }
        if (dtor == null) {
            return Response.err("No destructor found in class '" + cls + "'. Looked for ~" + cls
                    + " / *destructor* / scalar_deleting_destructor in the class namespace.");
        }

        List<Instruction> insns = new ArrayList<>();
        InstructionIterator iit = listing.getInstructions(dtor.getBody(), true);
        while (iit.hasNext()) insns.add(iit.next());

        // opDeleteSize: the size immediate forwarded to operator delete. In MSVC the scalar-deleting
        // destructor does `PUSH <size>` then calls operator delete; capture the constant pushed
        // nearest a call whose target name mentions "delete"/"free". Fallback: any size near such a call.
        Long opDeleteSize = null;
        List<String> baseChain = new ArrayList<>();
        List<String> memberFreeOffsets = new ArrayList<>();
        Set<String> seenFree = new LinkedHashSet<>();
        long highestMemberOffset = -1;

        for (int i = 0; i < insns.size(); i++) {
            Instruction insn = insns.get(i);
            String mn = insn.getMnemonicString();

            // Track this+0xNN writes for highestMemberOffset and member-free offset capture.
            if (insn.getNumOperands() >= 1 && (insn.getOperandType(0) & OperandType.DYNAMIC) != 0) {
                Matcher fm = FIELD_PAT.matcher(opMem(insn, 0));
                if (fm.matches() && fm.group(1) != null) {
                    long off = Long.parseLong(fm.group(1), 16);
                    if (off > highestMemberOffset) highestMemberOffset = off;
                }
            }

            if (!"CALL".equalsIgnoreCase(mn)) continue;
            Address tgt = null;
            for (Reference r : insn.getReferencesFrom()) {
                if (r.getReferenceType().isCall()) { tgt = r.getToAddress(); break; }
            }
            Function tf = tgt != null ? funcMgr.getFunctionAt(tgt) : null;
            String tname = tf != null ? tf.getName(true) : null;
            String lname = tname != null ? tname.toLowerCase() : "";

            // operator delete / free: capture the size immediate pushed for this call.
            if (lname.contains("delete") || lname.equals("free") || lname.endsWith("::free")
                    || lname.contains("operator.delete")) {
                Long sz = nearestPushedScalar(insns, i);
                if (sz != null && opDeleteSize == null) opDeleteSize = sz;
            }

            // Base-class chain: a CALL to another class's destructor.
            if (tf != null && isDestructorName(tf.getName(), tf.getParentNamespace() != null
                    ? tf.getParentNamespace().getName() : "")) {
                if (!baseChain.contains(tname)) baseChain.add(tname);
            }

            // Member-free / refcount-release: a vtable-slot call or free dispatched on this+0xNN.
            // The freed member is the ECX/this offset loaded just before the call.
            String memOff = memberOffsetBeforeCall(insns, i);
            if (memOff != null && (isDestructorName(tname, "") || lname.contains("release")
                    || lname.contains("free") || lname.contains("delete") || lname.contains("decref")
                    || lname.contains("removeref") || (tname == null && memOff != null))) {
                if (seenFree.add(memOff)) memberFreeOffsets.add(memOff);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("class_name", cls);
        result.put("dtorAddr", dtor.getEntryPoint().toString(false));
        result.put("opDeleteSize", opDeleteSize);
        result.put("baseChain", baseChain);
        result.put("memberFreeOffsets", memberFreeOffsets);
        result.put("memberCount", memberCount);
        result.put("highestMemberOffset", highestMemberOffset >= 0 ? "+0x" + Long.toHexString(highestMemberOffset) : null);
        return Response.ok(result);
    }

    /** Heuristic: does {@code fnName} look like a destructor for class {@code cls}? */
    private static boolean isDestructorName(String fnName, String cls) {
        if (fnName == null) return false;
        String n = fnName;
        if (n.contains("~")) return true;
        String lower = n.toLowerCase();
        if (lower.contains("destructor")) return true;          // scalar_deleting_destructor, ~Class_destructor
        if (lower.contains("_dtor") || lower.endsWith("dtor")) return true;
        // Itanium-style D0/D1/D2 complete/deleting destructors sometimes survive as suffixes.
        if (n.endsWith("D0Ev") || n.endsWith("D1Ev") || n.endsWith("D2Ev")) return true;
        return false;
    }

    /**
     * Walk back from a CALL at {@code callIdx} for the nearest PUSH of an immediate scalar
     * (the operator-delete size argument). Stops at the previous CALL. Returns null if none.
     */
    private Long nearestPushedScalar(List<Instruction> insns, int callIdx) {
        for (int j = callIdx - 1; j >= 0; j--) {
            Instruction p = insns.get(j);
            String pm = p.getMnemonicString();
            if ("CALL".equalsIgnoreCase(pm)) break;
            if (!"PUSH".equalsIgnoreCase(pm)) continue;
            int pt = p.getNumOperands() > 0 ? p.getOperandType(0) : 0;
            if ((pt & OperandType.SCALAR) != 0 && (pt & OperandType.DYNAMIC) == 0) {
                Scalar sc = firstScalar(p.getOpObjects(0));
                if (sc != null) return sc.getValue();
            }
        }
        return null;
    }

    /**
     * If the dispatch register for the CALL at {@code callIdx} (or a nearby ECX setup) was loaded
     * from {@code [ECX + 0xNN]} / {@code [this + 0xNN]}, return "+0xNN"; else null. Used to attribute
     * a member-release/free call to the owning field offset.
     */
    private String memberOffsetBeforeCall(List<Instruction> insns, int callIdx) {
        for (int j = callIdx; j >= 0 && j >= callIdx - 8; j--) {
            Instruction p = insns.get(j);
            String m = p.getMnemonicString();
            if (j != callIdx && "CALL".equalsIgnoreCase(m)) break;
            // Look for a MOV/LEA whose memory operand is [ECX/this + 0xNN].
            for (int op = 0; op < p.getNumOperands(); op++) {
                if ((p.getOperandType(op) & OperandType.DYNAMIC) == 0) continue;
                Matcher fm = FIELD_PAT.matcher(opMem(p, op));
                if (fm.matches() && fm.group(1) != null) {
                    return "+0x" + fm.group(1).toLowerCase();
                }
            }
        }
        return null;
    }

    @McpTool(path = "/get_vtable_slot_target", description = "Resolve a single vtable slot to the named function it points to. Accepts a vtable ADDRESS or a class name (resolves the class's vtable label '<class>::vftable' / '<class>_vtable'), and a slot given as a byte offset ('0xfc') or a slot index ('5'). Returns {vtable_address, slot_index, slot_offset, pointer, name}. Thin convenience over the same per-slot read as get_vtable_at (overlaps get_vtable_at, which dumps ALL slots). Read-only.", category = "listing")
    public Response getVtableSlotTarget(
            @Param(value = "class_or_vtable", description = "A vtable address (hex) OR a class name to resolve its vftable") String classOrVtable,
            @Param(value = "slot_offset", description = "Byte offset like '0xfc' or a slot index like '5'") String slotOffsetStr,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        if (classOrVtable == null || classOrVtable.trim().isEmpty()) return Response.err("class_or_vtable is required");
        if (slotOffsetStr == null || slotOffsetStr.trim().isEmpty()) return Response.err("slot_offset is required");
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        int ptrSize = program.getDefaultPointerSize();
        if (ptrSize != 4 && ptrSize != 8) return Response.err("Unsupported pointer size: " + ptrSize);

        // Resolve the vtable base: try as an address first, else as a class name.
        Address vtableAddr = ServiceUtils.parseAddress(program, classOrVtable.trim());
        String resolvedVia = "address";
        if (vtableAddr == null) {
            vtableAddr = resolveVtableByClassName(program, classOrVtable.trim());
            resolvedVia = "class-name";
            if (vtableAddr == null) {
                return Response.err("Could not resolve '" + classOrVtable + "' as a vtable address or a "
                        + "class vftable symbol. Tried labels '" + classOrVtable.trim() + "::vftable', '"
                        + classOrVtable.trim() + "_vtable', and similar.");
            }
        }

        // slot_offset: a byte offset ("0x..", or a value that is a multiple of ptrSize) vs a slot index.
        String so = slotOffsetStr.trim();
        long slotIndex;
        long byteOffset;
        boolean hex = so.toLowerCase().startsWith("0x");
        long raw;
        try {
            raw = hex ? Long.parseLong(so.substring(2), 16) : Long.parseLong(so);
        } catch (NumberFormatException e) {
            return Response.err("Invalid slot_offset '" + slotOffsetStr + "': expected hex byte offset (0xNN) or decimal slot index");
        }
        // A hex value, or any value that is a nonzero multiple of the pointer size, is a byte offset;
        // otherwise treat as a slot index. (Index 0 / small decimals -> index.)
        if (hex || (raw != 0 && raw % ptrSize == 0 && raw >= ptrSize)) {
            byteOffset = raw;
            slotIndex = raw / ptrSize;
        } else {
            slotIndex = raw;
            byteOffset = raw * ptrSize;
        }

        ghidra.program.model.mem.Memory memory = program.getMemory();
        FunctionManager funcMgr = program.getFunctionManager();
        try {
            Address slotAddr = vtableAddr.add(byteOffset);
            long fnPtr = (ptrSize == 4) ? (memory.getInt(slotAddr) & 0xFFFFFFFFL) : memory.getLong(slotAddr);
            Address fnAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(fnPtr);
            Function fn = funcMgr.getFunctionAt(fnAddr);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("vtable_address", vtableAddr.toString(false));
            result.put("resolved_via", resolvedVia);
            result.put("slot_index", slotIndex);
            result.put("slot_offset", "0x" + Long.toHexString(byteOffset));
            result.put("pointer", String.format("%08x", fnPtr));
            result.put("name", fn != null ? fn.getName(true) : "(no function)");
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to read slot at offset 0x" + Long.toHexString(byteOffset)
                    + " of vtable " + vtableAddr.toString(false) + ": " + e.getMessage()
                    + " (slot may be past the table end or in unmapped memory)");
        }
    }

    /** Resolve a class's vtable base address from common vftable label spellings. */
    private Address resolveVtableByClassName(Program program, String className) {
        SymbolTable st = program.getSymbolTable();
        // Candidate flat label spellings, most-specific first.
        String[] flat = {
            className + "::vftable", className + "::vtable", className + "_vtable",
            className + "_vftable", "vtable_" + className, className + "Vtbl"
        };
        for (String label : flat) {
            for (Symbol s : st.getGlobalSymbols(label)) {
                if (s.getAddress() != null && s.getAddress().isMemoryAddress()) return s.getAddress();
            }
        }
        // Namespaced: a symbol named 'vftable'/'vtable' inside the class namespace.
        Namespace ns = st.getNamespace(className, program.getGlobalNamespace());
        if (ns != null && !ns.isGlobal()) {
            for (Symbol s : st.getSymbols(ns)) {
                String n = s.getName();
                if ("vftable".equalsIgnoreCase(n) || "vtable".equalsIgnoreCase(n) || n.endsWith("vftable")) {
                    if (s.getAddress() != null && s.getAddress().isMemoryAddress()) return s.getAddress();
                }
            }
        }
        return null;
    }

    @McpTool(path = "/rename_class", method = "POST", description = "Atomically rename a C++ class: (a) the namespace symbol 'old_name' (which re-parents all member functions) AND (b) the this-type struct DataType '/old_name' if it exists. ABORTS if a namespace OR datatype named 'new_name' already exists (no blind merge). Returns {renamed_namespace, members_reparented, renamed_datatype, struct_size}. Runs in a transaction.", category = "rename")
    public Response renameClass(
            @Param(value = "old_name", source = ParamSource.BODY, description = "Existing class name") String oldName,
            @Param(value = "new_name", source = ParamSource.BODY, description = "New class name") String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        if (oldName == null || oldName.trim().isEmpty()) return Response.err("old_name is required");
        if (newName == null || newName.trim().isEmpty()) return Response.err("new_name is required");
        final String oldN = oldName.trim();
        final String newN = newName.trim();
        if (oldN.equals(newN)) return Response.err("old_name and new_name are identical");

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        SymbolTable st = program.getSymbolTable();
        Namespace global = program.getGlobalNamespace();
        DataTypeManager dtm = program.getDataTypeManager();

        // Locate the source namespace and/or datatype — at least one must exist.
        Namespace oldNs = st.getNamespace(oldN, global);
        if (oldNs != null && oldNs.isGlobal()) oldNs = null;
        DataType oldDt = ServiceUtils.findDataTypeByNameInAllCategories(dtm, oldN);
        if (oldNs == null && oldDt == null) {
            return Response.err("Neither a namespace nor a datatype named '" + oldN + "' exists.");
        }

        // Guard: refuse to merge into an existing target (namespace OR datatype).
        Namespace existingNs = st.getNamespace(newN, global);
        if (existingNs != null && !existingNs.isGlobal()) {
            return Response.err("A namespace named '" + newN + "' already exists — refusing to merge. "
                    + "Choose a different new_name or merge manually.");
        }
        if (ServiceUtils.findDataTypeByNameInAllCategories(dtm, newN) != null) {
            return Response.err("A datatype named '" + newN + "' already exists — refusing to merge. "
                    + "Choose a different new_name or merge manually.");
        }

        boolean renamedNs = false;
        boolean renamedDt = false;
        int membersReparented = 0;
        Integer structSize = null;

        int tx = program.startTransaction("Rename class " + oldN + " -> " + newN);
        boolean commit = false;
        try {
            if (oldNs != null) {
                // Count members BEFORE rename (they follow the namespace symbol automatically).
                FunctionManager funcMgr = program.getFunctionManager();
                for (Symbol s : st.getSymbols(oldNs)) {
                    Function f = funcMgr.getFunctionAt(s.getAddress());
                    if (f != null && oldNs.equals(f.getParentNamespace())) membersReparented++;
                }
                oldNs.getSymbol().setName(newN, SourceType.USER_DEFINED);
                renamedNs = true;
            }
            if (oldDt != null) {
                if (oldDt instanceof ghidra.program.model.data.Structure) {
                    structSize = ((ghidra.program.model.data.Structure) oldDt).getLength();
                }
                oldDt.setName(newN);
                renamedDt = true;
            }
            commit = true;
        } catch (Exception e) {
            return Response.err("rename_class failed: " + e.getMessage());
        } finally {
            // Commit on success, roll back on any failure (both the catch path and any
            // exception thrown while the catch's Response is built).
            program.endTransaction(tx, commit);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("renamed_namespace", renamedNs);
        result.put("members_reparented", membersReparented);
        result.put("renamed_datatype", renamedDt);
        result.put("struct_size", structSize);
        return Response.ok(result);
    }

    // Matches a memory reference like "[EDX + 0x4]" or "[ECX]" (positive displacement only;
    // vtable slot offsets are non-negative). group(1)=base register, group(2)=hex displacement.
    private static final Pattern MEM_PAT =
            Pattern.compile("\\[([A-Za-z0-9]+)(?:\\s*\\+\\s*0x([0-9a-fA-F]+))?\\]");

    /**
     * Backward dataflow: what does {@code reg} hold at instruction index {@code useIdx}?
     * Scans upward within the function for the nearest writer of {@code reg} and renders it
     * symbolically — {@code &[mem]} for LEA, {@code [mem](+|0xN)} for a MOV-from-memory whose
     * source was OR/AND/etc. with an immediate, a signed scalar for MOV-imm, or follows a
     * MOV reg,reg2 alias. Falls back to {@code reg:NAME} when the source can't be resolved.
     */
    private String resolveReg(List<Instruction> insns, int useIdx, String reg, int budget) {
        if (reg == null || budget <= 0) return "reg:" + reg;
        for (int j = useIdx - 1; j >= 0; j--) {
            Instruction p = insns.get(j);
            String m = p.getMnemonicString();
            if ("CALL".equalsIgnoreCase(m)) break; // a call clobbers volatile regs — stop
            if (p.getNumOperands() < 1) continue;
            int t0 = p.getOperandType(0);
            boolean op0IsReg = (t0 & OperandType.REGISTER) != 0 && (t0 & OperandType.DYNAMIC) == 0;
            if (!op0IsReg) continue;
            Register dst = firstReg(p.getOpObjects(0));
            if (dst == null || !dst.getName().equalsIgnoreCase(reg)) continue;
            // p defines reg
            if ("LEA".equalsIgnoreCase(m)) {
                return "&" + opMem(p, 1);
            }
            if ("MOV".equalsIgnoreCase(m)) {
                int t1 = p.getNumOperands() > 1 ? p.getOperandType(1) : 0;
                if ((t1 & OperandType.SCALAR) != 0 && (t1 & OperandType.DYNAMIC) == 0) {
                    Scalar s = firstScalar(p.getOpObjects(1));
                    return s != null ? Long.toString(s.getSignedValue()) : "reg:" + reg;
                } else if ((t1 & OperandType.DYNAMIC) != 0) {
                    String mr = opMem(p, 1);
                    return mr + scanImmArith(insns, j, mr);
                } else if ((t1 & OperandType.REGISTER) != 0) {
                    Register src = firstReg(p.getOpObjects(1));
                    if (src == null) return "reg:" + reg;
                    return resolveReg(insns, j, src.getName(), budget - 1);
                }
                return "reg:" + reg;
            }
            return "reg:" + reg; // ADD/SUB/XOR/POP/... — don't fabricate a value
        }
        return "reg:" + reg;
    }

    /** Render a memory operand as "[base + disp]", stripping any "dword ptr" size prefix. */
    private String opMem(Instruction p, int opIdx) {
        String rep = p.getDefaultOperandRepresentation(opIdx);
        if (rep == null) return "mem";
        int b = rep.indexOf('[');
        return b >= 0 ? rep.substring(b) : rep;
    }

    /**
     * Scan upward from {@code defIdx} for the nearest immediate arithmetic/logic op that wrote
     * the same memory location {@code memStr} (e.g. {@code OR [EBP+0xc],0x400}), and return a
     * compact annotation like "|0x400". Returns "" if the value was last set by a plain MOV or
     * nothing matched. Folds the operator-new hint bit into the forwarded flags argument.
     */
    private String scanImmArith(List<Instruction> insns, int defIdx, String memStr) {
        if (memStr == null || !memStr.startsWith("[")) return "";
        for (int j = defIdx - 1; j >= 0; j--) {
            Instruction p = insns.get(j);
            if (p.getNumOperands() < 2) continue;
            int t0 = p.getOperandType(0);
            if ((t0 & OperandType.DYNAMIC) == 0) continue;
            if (!memStr.equals(opMem(p, 0))) continue;
            Scalar s = firstScalar(p.getOpObjects(1));
            if (s == null) return ""; // wrote mem from a non-immediate — stop, can't fold
            String v = "0x" + Long.toHexString(s.getValue());
            switch (p.getMnemonicString().toUpperCase()) {
                case "OR":  return "|" + v;
                case "AND": return "&" + v;
                case "ADD": return "+" + v;
                case "SUB": return "-" + v;
                case "XOR": return "^" + v;
                default:    return ""; // MOV/other replaced the value — no fold
            }
        }
        return "";
    }

    private static Register firstReg(Object[] objs) {
        if (objs == null) return null;
        for (Object o : objs) if (o instanceof Register) return (Register) o;
        return null;
    }

    private static Scalar firstScalar(Object[] objs) {
        if (objs == null) return null;
        for (Object o : objs) if (o instanceof Scalar) return (Scalar) o;
        return null;
    }

    @McpTool(path = "/find_functions_referencing_string", description = "Find all functions that reference strings matching a regex pattern. Returns function name, address, and the matching string(s). Fast path to naming functions by their log/error messages.", category = "listing")
    public Response findFunctionsReferencingString(
            @Param(value = "pattern", description = "Regex pattern to match against string values (case-insensitive)") String patternStr,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (patternStr == null || patternStr.isEmpty()) return Response.err("pattern is required");

        Pattern pat;
        try {
            pat = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return Response.err("Invalid regex: " + e.getMessage());
        }

        FunctionManager funcMgr = program.getFunctionManager();
        ghidra.program.model.symbol.ReferenceManager refMgr = program.getReferenceManager();

        Map<Address, Map<String, Object>> byFunction = new LinkedHashMap<>();

        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data == null || !ServiceUtils.isStringData(data)) continue;
            String value = data.getValue() != null ? data.getValue().toString() : "";
            if (!pat.matcher(value).find()) continue;

            ghidra.program.model.symbol.ReferenceIterator refs = refMgr.getReferencesTo(data.getAddress());
            while (refs.hasNext()) {
                ghidra.program.model.symbol.Reference ref = refs.next();
                Function fn = funcMgr.getFunctionContaining(ref.getFromAddress());
                if (fn == null) continue;
                Address key = fn.getEntryPoint();
                if (!byFunction.containsKey(key)) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("name", fn.getName(true));
                    entry.put("address", key.toString(false));
                    entry.put("strings", new ArrayList<String>());
                    byFunction.put(key, entry);
                }
                @SuppressWarnings("unchecked")
                List<String> strings = (List<String>) byFunction.get(key).get("strings");
                if (!strings.contains(value)) strings.add(value);
            }
        }

        List<Map<String, Object>> results = new ArrayList<>(byFunction.values());
        int total = results.size();
        int from = Math.min(offset, total);
        int to = Math.min(from + limit, total);

        return Response.ok(JsonHelper.mapOf(
                "matches", results.subList(from, to),
                "total", total,
                "pattern", patternStr,
                "offset", offset,
                "limit", limit
        ));
    }
}
