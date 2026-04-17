package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.util.*;
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

    @McpTool(path = "/list_data_items_by_xrefs", description = "List data items sorted by cross-reference count", category = "listing")
    public Response listDataItemsByXrefs(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "format", defaultValue = "text", description = "Output format (text or json)") String format,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<DataItemInfo> dataItems = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    Address addr = data.getAddress();
                    int xrefCount = refMgr.getReferenceCountTo(addr);

                    String label = data.getLabel() != null ? data.getLabel() :
                                   "DAT_" + addr.toString(false);

                    DataType dt = data.getDataType();
                    String typeName = (dt != null) ? dt.getName() : "undefined";
                    int length = data.getLength();

                    dataItems.add(new DataItemInfo(addr.toString(false), label, typeName, length, xrefCount));
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
            funcItem.put("isThunk", func.isThunk());
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
     * fully-qualified (namespace-prefixed) name. A prefix can therefore target
     * a namespace (e.g. "GRScript::"), a simple-name prefix (e.g. "FUN_"), or
     * a fully-qualified prefix (e.g. "GRScript::Helper_").
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

        // Map from function entry → {function, list of matching strings}
        Map<Address, Map<String, Object>> byFunction = new LinkedHashMap<>();

        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data == null || !ServiceUtils.isStringData(data)) continue;
            String value = data.getValue() != null ? data.getValue().toString() : "";
            if (!pat.matcher(value).find()) continue;

            // Find functions that reference this string's address
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

    @McpTool(path = "/list_globals", description = "List global symbols with optional filter", category = "listing")
    public Response listGlobals(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "filter", description = "Substring filter", defaultValue = "") String filter,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> globals = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();

        Namespace globalNamespace = program.getGlobalNamespace();
        SymbolIterator symbols = symbolTable.getSymbols(globalNamespace);

        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                continue;
            }

            String symbolInfo = formatGlobalSymbol(symbol);
            if (filter == null || filter.isEmpty() ||
                symbolInfo.toLowerCase().contains(filter.toLowerCase())) {
                globals.add(symbolInfo);
            }
        }

        return Response.text(ServiceUtils.paginateList(globals, offset, limit));
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
}
