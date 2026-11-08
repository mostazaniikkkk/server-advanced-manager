package dev.sam.common.perms;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

/**
 * Los permisos nativos de SAM (RF-PERM, docs/PERMISOS.md): grupos con peso y herencia, nodos con comodín y
 * negación, metas, vencimientos y nodos que exigen sesión verificada. Inmutable; se lee y se escribe como
 * {@code config/sam/permissions.json} con lectura estricta. Los nicks van en minúsculas.
 */
public record PermissionSet(Map<String, Group> groups, Map<String, User> users) {

    public static final String DEFAULT = "default";
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int MAX_GROUPS = 256;
    private static final int MAX_NODES = 1024;
    private static final int MAX_META = 256;
    private static final int MAX_PARENTS = 16;
    private static final int MAX_META_VALUE = 256;
    private static final int MAX_NODE = 128;
    private static final Pattern GROUP = Pattern.compile("[a-z0-9_-]{1,32}");
    private static final Pattern NICK = Pattern.compile("[a-z0-9_]{1,16}");
    private static final Pattern NODE = Pattern.compile("\\*|[a-z0-9_-]+(\\.[a-z0-9_-]+)*(\\.\\*)?");
    private static final Pattern META = Pattern.compile("[a-z0-9_-]+(\\.[a-z0-9_-]+)*");

    /** El resultado de una consulta: indefinido si ninguna fuente dice nada. */
    public enum Value {
        TRUE, FALSE, UNDEFINED
    }

    /** El valor y, si lo hay, qué fuente y qué entrada lo decidió (para {@code /sam perms check}). */
    public record Check(Value value, Optional<String> source, Optional<String> entry) {
    }

    /** Un nodo concedido ({@code true}) o negado ({@code false}), quizá temporal o solo con sesión verificada. */
    public record Grant(boolean value, OptionalLong expires, boolean verified) {
    }

    public record Meta(String value, OptionalLong expires) {
    }

    public record Group(int weight, List<String> parents, Map<String, Grant> permissions, Map<String, Meta> meta) {

        public Group {
            parents = List.copyOf(parents);
            permissions = Map.copyOf(permissions);
            meta = Map.copyOf(meta);
        }
    }

    /** @param groups grupo → vencimiento (vacío si no vence) */
    public record User(Map<String, OptionalLong> groups, Map<String, Grant> permissions, Map<String, Meta> meta) {

        public User {
            groups = Map.copyOf(groups);
            permissions = Map.copyOf(permissions);
            meta = Map.copyOf(meta);
        }
    }

    /** El conjunto sin lo vencido y qué se quitó (para la auditoría). */
    public record Expiry(PermissionSet set, List<String> removed) {
    }

    public PermissionSet {
        groups = Map.copyOf(groups);
        users = Map.copyOf(users);
    }

    /** Solo el grupo {@code default}, vacío. */
    public static PermissionSet empty() {
        return new PermissionSet(Map.of(DEFAULT, new Group(0, List.of(), Map.of(), Map.of())), Map.of());
    }

    // ===== Resolución (docs/PERMISOS.md, sección 2) =====

    public Check check(String nick, String node, long now, boolean verified) {
        var user = users.get(nick.toLowerCase(java.util.Locale.ROOT));
        var sources = new ArrayList<Map.Entry<String, Map<String, Grant>>>();
        if (user != null) {
            sources.add(Map.entry("jugador", user.permissions()));
        }
        for (var group : groupsOf(user, now)) {
            sources.add(Map.entry("grupo " + group, groups.get(group).permissions()));
        }
        for (var source : sources) {
            for (var candidate : candidates(node)) {
                var grant = source.getValue().get(candidate);
                if (grant != null && valid(grant.expires(), now) && (verified || !grant.verified())) {
                    return new Check(grant.value() ? Value.TRUE : Value.FALSE, Optional.of(source.getKey()), Optional.of(candidate));
                }
            }
        }
        return new Check(Value.UNDEFINED, Optional.empty(), Optional.empty());
    }

    public Optional<String> meta(String nick, String key, long now) {
        var user = users.get(nick.toLowerCase(java.util.Locale.ROOT));
        var sources = new ArrayList<Map<String, Meta>>();
        if (user != null) {
            sources.add(user.meta());
        }
        groupsOf(user, now).forEach(group -> sources.add(groups.get(group).meta()));
        for (var source : sources) {
            var meta = source.get(key);
            if (meta != null && valid(meta.expires(), now)) {
                return Optional.of(meta.value());
            }
        }
        return Optional.empty();
    }

    /** El nodo exacto y después sus comodines, del más largo al más corto. */
    private static List<String> candidates(String node) {
        var candidates = new ArrayList<String>();
        candidates.add(node);
        var parts = node.split("\\.");
        for (var i = parts.length - 1; i >= 1; i--) {
            candidates.add(String.join(".", java.util.Arrays.copyOf(parts, i)) + ".*");
        }
        candidates.add("*");
        return candidates;
    }

    /** Los grupos del jugador (directos vigentes, heredados y default), de mayor a menor peso. */
    private List<String> groupsOf(User user, long now) {
        var pending = new ArrayDeque<String>();
        if (user != null) {
            user.groups().forEach((group, expires) -> {
                if (valid(expires, now)) {
                    pending.add(group);
                }
            });
        }
        pending.add(DEFAULT);
        var all = new LinkedHashSet<String>();
        while (!pending.isEmpty()) {
            var group = pending.poll();
            if (all.add(group)) {
                pending.addAll(groups.get(group).parents());
            }
        }
        return all.stream().sorted(Comparator.comparingInt((String g) -> -groups.get(g).weight()).thenComparing(g -> g)).toList();
    }

    private static boolean valid(OptionalLong expires, long now) {
        return expires.isEmpty() || now < expires.getAsLong();
    }

    // ===== Vencimientos =====

    public Expiry expire(long now) {
        var removed = new ArrayList<String>();
        var newGroups = new TreeMap<String, Group>();
        new TreeMap<>(groups).forEach((name, group) -> newGroups.put(name, new Group(group.weight(), group.parents(),
            alive(group.permissions(), Grant::expires, now, "grupo " + name + ": ", "", removed),
            alive(group.meta(), Meta::expires, now, "grupo " + name + ": ", "meta ", removed))));
        var newUsers = new TreeMap<String, User>();
        new TreeMap<>(users).forEach((nick, user) -> {
            var memberships = new TreeMap<String, OptionalLong>();
            new TreeMap<>(user.groups()).forEach((group, expires) -> {
                if (valid(expires, now)) {
                    memberships.put(group, expires);
                } else {
                    removed.add(nick + ": grupo " + group);
                }
            });
            newUsers.put(nick, new User(memberships, alive(user.permissions(), Grant::expires, now, nick + ": ", "", removed),
                alive(user.meta(), Meta::expires, now, nick + ": ", "meta ", removed)));
        });
        return new Expiry(new PermissionSet(newGroups, newUsers), removed);
    }

    private static <T> Map<String, T> alive(Map<String, T> entries, java.util.function.Function<T, OptionalLong> expires, long now,
            String owner, String kind, List<String> removed) {
        var kept = new TreeMap<String, T>();
        new TreeMap<>(entries).forEach((key, value) -> {
            if (valid(expires.apply(value), now)) {
                kept.put(key, value);
            } else {
                removed.add(owner + kind + key);
            }
        });
        return kept;
    }

    // ===== Lectura estricta =====

    /** @throws IllegalArgumentException con el motivo si el archivo no es válido */
    public static PermissionSet parse(String json) {
        if (json.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw invalid("supera 1 MiB");
        }
        Object tree;
        try {
            var reader = new JsonReader(new StringReader(json));
            tree = read(reader);
            // En modo estricto, peek lanza si hay algo después del objeto
            reader.peek();
        } catch (IOException | IllegalStateException e) {
            throw invalid("no es JSON válido");
        }
        var root = object(tree, "el archivo");
        fields(root, Set.of("version", "groups", "users"));
        if (!new NumberText("1").equals(root.get("version"))) {
            throw invalid("version debe ser 1");
        }
        var groupsJson = object(root.getOrDefault("groups", Map.of()), "groups");
        if (groupsJson.size() > MAX_GROUPS) {
            throw invalid("como mucho " + MAX_GROUPS + " grupos");
        }
        var groups = new TreeMap<String, Group>();
        for (var entry : groupsJson.entrySet()) {
            if (!GROUP.matcher(entry.getKey()).matches()) {
                throw invalid("nombre de grupo inválido \"" + entry.getKey() + "\"");
            }
            groups.put(entry.getKey(), group(object(entry.getValue(), "el grupo " + entry.getKey())));
        }
        groups.putIfAbsent(DEFAULT, new Group(0, List.of(), Map.of(), Map.of()));
        for (var entry : groups.entrySet()) {
            for (var parent : entry.getValue().parents()) {
                if (!groups.containsKey(parent)) {
                    throw invalid("el grupo " + entry.getKey() + " hereda de " + parent + ", que no existe");
                }
            }
        }
        for (var name : groups.keySet()) {
            checkCycle(groups, name, new HashSet<>());
        }
        var usersJson = object(root.getOrDefault("users", Map.of()), "users");
        var users = new TreeMap<String, User>();
        for (var entry : usersJson.entrySet()) {
            if (!NICK.matcher(entry.getKey()).matches()) {
                throw invalid("nick inválido \"" + entry.getKey() + "\" (en minúsculas)");
            }
            var user = object(entry.getValue(), "el jugador " + entry.getKey());
            fields(user, Set.of("groups", "permissions", "meta"));
            var memberships = new TreeMap<String, OptionalLong>();
            for (var membership : object(user.getOrDefault("groups", Map.of()), "groups").entrySet()) {
                if (!groups.containsKey(membership.getKey())) {
                    throw invalid(entry.getKey() + " está en el grupo " + membership.getKey() + ", que no existe");
                }
                var details = object(membership.getValue(), "la pertenencia a " + membership.getKey());
                fields(details, Set.of("expires"));
                memberships.put(membership.getKey(), expires(details, membership.getKey()));
            }
            users.put(entry.getKey(), new User(memberships, permissions(user), metas(user)));
        }
        return new PermissionSet(groups, users);
    }

    private static Group group(Map<String, Object> json) {
        fields(json, Set.of("weight", "parents", "permissions", "meta"));
        var weight = json.containsKey("weight") ? (int) integer(json.get("weight"), "weight", Integer.MIN_VALUE, Integer.MAX_VALUE) : 0;
        var parents = new ArrayList<String>();
        if (json.containsKey("parents")) {
            if (!(json.get("parents") instanceof List<?> list)) {
                throw invalid("parents debe ser una lista de grupos");
            }
            if (list.size() > MAX_PARENTS) {
                throw invalid("como mucho " + MAX_PARENTS + " padres");
            }
            for (var parent : list) {
                if (!(parent instanceof String name) || !GROUP.matcher(name).matches()) {
                    throw invalid("parents debe ser una lista de grupos");
                }
                parents.add(name);
            }
        }
        return new Group(weight, parents, permissions(json), metas(json));
    }

    private static void checkCycle(Map<String, Group> groups, String group, Set<String> path) {
        if (!path.add(group)) {
            throw invalid("herencia circular en " + path.iterator().next());
        }
        for (var parent : groups.get(group).parents()) {
            checkCycle(groups, parent, path);
        }
        path.remove(group);
    }

    private static Map<String, Grant> permissions(Map<String, Object> holder) {
        var json = object(holder.getOrDefault("permissions", Map.of()), "permissions");
        if (json.size() > MAX_NODES) {
            throw invalid("como mucho " + MAX_NODES + " nodos");
        }
        var grants = new TreeMap<String, Grant>();
        for (var entry : json.entrySet()) {
            var node = entry.getKey();
            if (node.length() > MAX_NODE || !NODE.matcher(node).matches()) {
                throw invalid("nodo inválido \"" + node + "\"");
            }
            if (entry.getValue() instanceof Boolean value) {
                grants.put(node, new Grant(value, OptionalLong.empty(), false));
            } else if (entry.getValue() instanceof Map<?, ?>) {
                var grant = object(entry.getValue(), node);
                fields(grant, Set.of("value", "expires", "verified"));
                if (!(grant.get("value") instanceof Boolean value)) {
                    throw invalid(node + ": falta value");
                }
                var verified = grant.getOrDefault("verified", false);
                if (!(verified instanceof Boolean flag)) {
                    throw invalid(node + ": verified debe ser true o false");
                }
                grants.put(node, new Grant(value, expires(grant, node), flag));
            } else {
                throw invalid(node + ": el valor debe ser true, false o un objeto");
            }
        }
        return grants;
    }

    private static Map<String, Meta> metas(Map<String, Object> holder) {
        var json = object(holder.getOrDefault("meta", Map.of()), "meta");
        if (json.size() > MAX_META) {
            throw invalid("como mucho " + MAX_META + " metas");
        }
        var metas = new TreeMap<String, Meta>();
        for (var entry : json.entrySet()) {
            var key = entry.getKey();
            if (key.length() > MAX_NODE || !META.matcher(key).matches()) {
                throw invalid("meta inválida \"" + key + "\"");
            }
            String value;
            OptionalLong expires = OptionalLong.empty();
            if (entry.getValue() instanceof String text) {
                value = text;
            } else if (entry.getValue() instanceof Map<?, ?>) {
                var meta = object(entry.getValue(), key);
                fields(meta, Set.of("value", "expires"));
                if (!(meta.get("value") instanceof String text)) {
                    throw invalid(key + ": falta value");
                }
                value = text;
                expires = expires(meta, key);
            } else {
                throw invalid(key + ": el valor debe ser un texto o un objeto");
            }
            if (value.length() > MAX_META_VALUE) {
                throw invalid("la meta " + key + " supera los " + MAX_META_VALUE + " caracteres");
            }
            metas.put(key, new Meta(value, expires));
        }
        return metas;
    }

    private static OptionalLong expires(Map<String, Object> json, String owner) {
        if (!json.containsKey("expires")) {
            return OptionalLong.empty();
        }
        return OptionalLong.of(integer(json.get("expires"), owner + ": expires", 0, Long.MAX_VALUE));
    }

    /** Un número JSON tal como está escrito (para no aceptar decimales ni exponentes en silencio). */
    private record NumberText(String text) {
    }

    /** Solo enteros escritos sin decimales ni exponente, dentro de {@code [min, max]}. */
    private static long integer(Object value, String what, long min, long max) {
        if (!(value instanceof NumberText number) || !number.text().matches("-?\\d{1,18}")) {
            throw invalid(what + " debe ser un entero");
        }
        var parsed = Long.parseLong(number.text());
        if (parsed < min || parsed > max) {
            throw invalid(what + " fuera de rango");
        }
        return parsed;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value, String what) {
        if (!(value instanceof Map<?, ?>)) {
            throw invalid(what + " debe ser un objeto");
        }
        return (Map<String, Object>) value;
    }

    private static void fields(Map<String, Object> json, Set<String> allowed) {
        for (var name : json.keySet()) {
            if (!allowed.contains(name)) {
                throw invalid("campo desconocido \"" + name + "\"");
            }
        }
    }

    /** Un valor JSON como Map (sin claves repetidas), List, String (también los números, como su texto) o Boolean. */
    private static Object read(JsonReader reader) throws IOException {
        switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                var map = new LinkedHashMap<String, Object>();
                reader.beginObject();
                while (reader.hasNext()) {
                    var name = reader.nextName();
                    if (map.containsKey(name)) {
                        throw invalid("campo repetido \"" + name + "\"");
                    }
                    map.put(name, read(reader));
                }
                reader.endObject();
                return map;
            }
            case BEGIN_ARRAY -> {
                var list = new ArrayList<Object>();
                reader.beginArray();
                while (reader.hasNext()) {
                    list.add(read(reader));
                }
                reader.endArray();
                return list;
            }
            case BOOLEAN -> {
                return reader.nextBoolean();
            }
            case NUMBER -> {
                return new NumberText(reader.nextString());
            }
            case STRING -> {
                return reader.nextString();
            }
            default -> throw invalid("no es JSON válido");
        }
    }

    // ===== Escritura =====

    /** El archivo, ordenado y con sangría de dos espacios: siempre el mismo texto para el mismo contenido. */
    public String toJson() {
        var out = new StringWriter();
        try (var writer = new JsonWriter(out)) {
            writer.setIndent("  ");
            writer.beginObject().name("version").value(1);
            writer.name("groups").beginObject();
            for (var entry : new TreeMap<>(groups).entrySet()) {
                var group = entry.getValue();
                writer.name(entry.getKey()).beginObject().name("weight").value(group.weight());
                writer.name("parents").beginArray();
                for (var parent : group.parents()) {
                    writer.value(parent);
                }
                writer.endArray();
                writeHolder(writer, group.permissions(), group.meta());
                writer.endObject();
            }
            writer.endObject().name("users").beginObject();
            for (var entry : new TreeMap<>(users).entrySet()) {
                var user = entry.getValue();
                writer.name(entry.getKey()).beginObject().name("groups").beginObject();
                for (var membership : new TreeMap<>(user.groups()).entrySet()) {
                    writer.name(membership.getKey()).beginObject();
                    if (membership.getValue().isPresent()) {
                        writer.name("expires").value(membership.getValue().getAsLong());
                    }
                    writer.endObject();
                }
                writer.endObject();
                writeHolder(writer, user.permissions(), user.meta());
                writer.endObject();
            }
            writer.endObject().endObject();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out + "\n";
    }

    private static void writeHolder(JsonWriter writer, Map<String, Grant> permissions, Map<String, Meta> meta) throws IOException {
        writer.name("permissions").beginObject();
        for (var entry : new TreeMap<>(permissions).entrySet()) {
            var grant = entry.getValue();
            writer.name(entry.getKey());
            if (grant.expires().isEmpty() && !grant.verified()) {
                writer.value(grant.value());
            } else {
                writer.beginObject().name("value").value(grant.value());
                if (grant.expires().isPresent()) {
                    writer.name("expires").value(grant.expires().getAsLong());
                }
                if (grant.verified()) {
                    writer.name("verified").value(true);
                }
                writer.endObject();
            }
        }
        writer.endObject().name("meta").beginObject();
        for (var entry : new TreeMap<>(meta).entrySet()) {
            writer.name(entry.getKey());
            if (entry.getValue().expires().isEmpty()) {
                writer.value(entry.getValue().value());
            } else {
                writer.beginObject().name("value").value(entry.getValue().value()).name("expires")
                    .value(entry.getValue().expires().getAsLong()).endObject();
            }
        }
        writer.endObject();
    }

    // ===== Cambios (/sam perms, docs/PERMISOS.md sección 4) =====
    // Cada cambio arma el conjunto nuevo y lo pasa por la misma lectura estricta que el archivo.

    /**
     * H-07 (separación de funciones): si el cambio toca a ese jugador, en su entrada o en un grupo que le aplica
     * (directo vigente, heredado o {@code default}), antes o después del cambio.
     */
    public static boolean affects(PermissionSet before, PermissionSet after, String nick, long now) {
        var key = nick.toLowerCase(java.util.Locale.ROOT);
        if (!Objects.equals(before.users().get(key), after.users().get(key))) {
            return true;
        }
        var mine = new HashSet<>(before.groupsOf(before.users().get(key), now));
        mine.addAll(after.groupsOf(after.users().get(key), now));
        return mine.stream().anyMatch(group -> !Objects.equals(before.groups().get(group), after.groups().get(group)));
    }

    /** H-09: qué cambió entre dos estados, entidad por entidad ("grupo x: antes -> después; ..."), en una línea. */
    public static String diff(PermissionSet before, PermissionSet after) {
        var changes = new ArrayList<String>();
        var groupNames = new TreeSet<>(before.groups().keySet());
        groupNames.addAll(after.groups().keySet());
        for (var name : groupNames) {
            if (!Objects.equals(before.groups().get(name), after.groups().get(name))) {
                changes.add("grupo " + name + ": " + entity(before, "groups", name, "(no existía)") + " -> "
                    + entity(after, "groups", name, "(borrado)"));
            }
        }
        var userNames = new TreeSet<>(before.users().keySet());
        userNames.addAll(after.users().keySet());
        for (var name : userNames) {
            if (!Objects.equals(before.users().get(name), after.users().get(name))) {
                changes.add("jugador " + name + ": " + entity(before, "users", name, "(no existía)") + " -> "
                    + entity(after, "users", name, "(borrado)"));
            }
        }
        return String.join("; ", changes);
    }

    /** El JSON compacto de un grupo o un jugador, como se guarda en el archivo. */
    private static String entity(PermissionSet set, String kind, String name, String missing) {
        var json = com.google.gson.JsonParser.parseString(set.toJson()).getAsJsonObject().getAsJsonObject(kind).get(name);
        return json == null ? missing : json.toString();
    }

    public PermissionSet createGroup(String name, int weight) {
        if (groups.containsKey(name)) {
            throw change("el grupo " + name + " ya existe");
        }
        var copy = new TreeMap<>(groups);
        copy.put(name, new Group(weight, List.of(), Map.of(), Map.of()));
        return validated(copy, users);
    }

    public PermissionSet deleteGroup(String name) {
        group(name);
        if (name.equals(DEFAULT)) {
            throw change("el grupo default no se puede borrar");
        }
        for (var entry : new TreeMap<>(groups).entrySet()) {
            if (entry.getValue().parents().contains(name)) {
                throw change(name + " es padre de " + entry.getKey() + ": quítalo de ahí primero");
            }
        }
        var copy = new TreeMap<>(groups);
        copy.remove(name);
        var newUsers = new TreeMap<String, User>();
        users.forEach((nick, user) -> {
            var memberships = new TreeMap<>(user.groups());
            memberships.remove(name);
            newUsers.put(nick, new User(memberships, user.permissions(), user.meta()));
        });
        return validated(copy, newUsers);
    }

    public PermissionSet setWeight(String group, int weight) {
        var old = group(group);
        return withGroup(group, new Group(weight, old.parents(), old.permissions(), old.meta()));
    }

    public PermissionSet addParent(String group, String parent) {
        var old = group(group);
        group(parent);
        if (old.parents().contains(parent)) {
            throw change(group + " ya hereda de " + parent);
        }
        var parents = new ArrayList<>(old.parents());
        parents.add(parent);
        return withGroup(group, new Group(old.weight(), parents, old.permissions(), old.meta()));
    }

    public PermissionSet removeParent(String group, String parent) {
        var old = group(group);
        if (!old.parents().contains(parent)) {
            throw change(group + " no hereda de " + parent);
        }
        var parents = new ArrayList<>(old.parents());
        parents.remove(parent);
        return withGroup(group, new Group(old.weight(), parents, old.permissions(), old.meta()));
    }

    public PermissionSet setGroupPermission(String group, String node, Grant grant) {
        var old = group(group);
        var permissions = new TreeMap<>(old.permissions());
        permissions.put(node, grant);
        return withGroup(group, new Group(old.weight(), old.parents(), permissions, old.meta()));
    }

    public PermissionSet unsetGroupPermission(String group, String node) {
        var old = group(group);
        var permissions = new TreeMap<>(old.permissions());
        if (permissions.remove(node) == null) {
            throw change(group + " no tiene el nodo " + node);
        }
        return withGroup(group, new Group(old.weight(), old.parents(), permissions, old.meta()));
    }

    public PermissionSet setGroupMeta(String group, String key, Meta meta) {
        var old = group(group);
        var metas = new TreeMap<>(old.meta());
        metas.put(key, meta);
        return withGroup(group, new Group(old.weight(), old.parents(), old.permissions(), metas));
    }

    public PermissionSet unsetGroupMeta(String group, String key) {
        var old = group(group);
        var metas = new TreeMap<>(old.meta());
        if (metas.remove(key) == null) {
            throw change(group + " no tiene la meta " + key);
        }
        return withGroup(group, new Group(old.weight(), old.parents(), old.permissions(), metas));
    }

    public PermissionSet addUserGroup(String nick, String group, OptionalLong expires) {
        group(group);
        var old = user(nick);
        var memberships = new TreeMap<>(old.groups());
        memberships.put(group, expires);
        return withUser(nick, new User(memberships, old.permissions(), old.meta()));
    }

    public PermissionSet removeUserGroup(String nick, String group) {
        var old = user(nick);
        var memberships = new TreeMap<>(old.groups());
        if (memberships.remove(group) == null) {
            throw change(key(nick) + " no está en el grupo " + group);
        }
        return withUser(nick, new User(memberships, old.permissions(), old.meta()));
    }

    public PermissionSet setUserPermission(String nick, String node, Grant grant) {
        var old = user(nick);
        var permissions = new TreeMap<>(old.permissions());
        permissions.put(node, grant);
        return withUser(nick, new User(old.groups(), permissions, old.meta()));
    }

    public PermissionSet unsetUserPermission(String nick, String node) {
        var old = user(nick);
        var permissions = new TreeMap<>(old.permissions());
        if (permissions.remove(node) == null) {
            throw change(key(nick) + " no tiene el nodo " + node);
        }
        return withUser(nick, new User(old.groups(), permissions, old.meta()));
    }

    public PermissionSet setUserMeta(String nick, String key, Meta meta) {
        var old = user(nick);
        var metas = new TreeMap<>(old.meta());
        metas.put(key, meta);
        return withUser(nick, new User(old.groups(), old.permissions(), metas));
    }

    public PermissionSet unsetUserMeta(String nick, String key) {
        var old = user(nick);
        var metas = new TreeMap<>(old.meta());
        if (metas.remove(key) == null) {
            throw change(key(nick) + " no tiene la meta " + key);
        }
        return withUser(nick, new User(old.groups(), old.permissions(), metas));
    }

    private Group group(String name) {
        var group = groups.get(name);
        if (group == null) {
            throw change("no existe el grupo " + name);
        }
        return group;
    }

    private static String key(String nick) {
        return nick.toLowerCase(java.util.Locale.ROOT);
    }

    private User user(String nick) {
        return users.getOrDefault(key(nick), new User(Map.of(), Map.of(), Map.of()));
    }

    private PermissionSet withGroup(String name, Group group) {
        var copy = new TreeMap<>(groups);
        copy.put(name, group);
        return validated(copy, users);
    }

    private PermissionSet withUser(String nick, User user) {
        var copy = new TreeMap<>(users);
        copy.put(key(nick), user);
        return validated(groups, copy);
    }

    /** El conjunto nuevo, sin jugadores vacíos, validado con las reglas del archivo. */
    private static PermissionSet validated(Map<String, Group> groups, Map<String, User> users) {
        var kept = new TreeMap<String, User>();
        users.forEach((nick, user) -> {
            if (!user.groups().isEmpty() || !user.permissions().isEmpty() || !user.meta().isEmpty()) {
                kept.put(nick, user);
            }
        });
        try {
            return parse(new PermissionSet(groups, kept).toJson());
        } catch (IllegalArgumentException e) {
            throw change(e.getMessage().substring("permissions.json inválido: ".length()));
        }
    }

    private static IllegalArgumentException change(String reason) {
        return new IllegalArgumentException(reason);
    }

    private static final Pattern DURATION = Pattern.compile("(?:(\\d{1,4})d)?(?:(\\d{1,5})h)?(?:(\\d{1,6})m)?(?:(\\d{1,8})s)?");
    private static final long MAX_DURATION = 3650L * 86_400;

    /** Una duración como {@code 30d}, {@code 12h}, {@code 45m}, {@code 90s} o {@code 1d12h}, en segundos (hasta 3650 días). */
    public static long duration(String text) {
        var matcher = DURATION.matcher(text);
        var seconds = 0L;
        if (matcher.matches()) {
            long[] units = {86_400, 3600, 60, 1};
            for (var i = 0; i < units.length; i++) {
                var group = matcher.group(i + 1);
                if (group != null) {
                    seconds += Long.parseLong(group) * units[i];
                }
            }
        }
        if (seconds <= 0 || seconds > MAX_DURATION) {
            throw new IllegalArgumentException("duración inválida \"" + text + "\": por ejemplo 30d, 12h, 45m, 90s o 1d12h (hasta 3650d)");
        }
        return seconds;
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException("permissions.json inválido: " + reason);
    }
}
