# Reglas de Cursor de ValeERP

Fecha: 10 de noviembre de 2026.

Este archivo solo guarda las reglas. Hay que ponerlas en la raíz del espacio de trabajo, en `.cursor/rules/`, un archivo `.mdc` por cada bloque. La raíz es la carpeta que abre Cursor, la de la tesis, no la carpeta de este servicio.

## file-size.mdc

````md
---
description: Límite de tamaño por archivo de código
alwaysApply: true
---

# Tamaño de archivo

- Un archivo de código llega como máximo a **559 líneas**. 600 es el tope duro: no lo cruces.
- Si el cambio siguiente pasaría de 559, parte el archivo antes de editar.
- Cuenta `.java`, `.ts`, `.tsx`, `.css` y `.mdc`. Excluye generados, `target/`, `node_modules/` y lockfiles.
- Parte por responsabilidad: un agregado, un caso de uso, una sección de página o un grupo de endpoints. No partes a la mitad de una clase solo por el número.
- Al extraer, el archivo original conserva el nombre del concepto principal. El nuevo archivo nombra la parte extraída.
````

## no-hardcode.mdc

````md
---
description: Prohibido dejar literales de negocio, URLs y umbrales en el código
alwaysApply: true
---

# Sin valores fijos en el código

Un literal de configuración o de negocio no se escribe en un controlador, servicio, página o cliente HTTP.

Va en un solo lugar, según quién lo posee:

- Entorno y despliegue (`VITE_*`, `application.properties`, variables de entorno): URL base, puerto, audience de Auth0, claim de roles.
- Política del contexto (enum, value object o clase de constantes del dominio): IGV, códigos de cuenta, moneda `PEN`, días de crédito por defecto, umbral de stock, estados.
- Parámetro de catálogo persistido cuando el negocio lo cambia sin redeploy: tasa de impuesto, método de pago, promoción.

```java
// Mal: el cliente y el asiento inventan el impuesto
double base = total / 1.18;

// Bien: la tasa sale del impuesto vigente del contexto
Money tax = totals.taxOf(sale.taxRate());
```

```ts
// Mal
const SALES_URL = "http://localhost:8083/api/store/sales";

// Bien
const SALES_URL = `${import.meta.env.VITE_STORE_API_URL}/sales`;
```

- El frontend no recalcula totales, descuentos ni stock que el agregado deba garantizar. Muestra lo que el caso de uso devuelve.
- Un número suelto de UI (columnas, debounce, `staleTime`) puede quedar local si no es una regla de negocio. Nómbralo.
- Los tests pueden usar fixtures literales.
````

## soft-delete.mdc

````md
---
description: Ningún registro se borra físicamente; la baja es lógica o un contra-asiento
alwaysApply: true
---

# Baja lógica, nunca delete físico

No existe borrado físico de filas de negocio. Prohibido `delete`, `deleteById`, `deleteAll`, `repository.delete`, `TRUNCATE` y un `DELETE` HTTP que ejecute un `DELETE` SQL.

## Maestros

Producto, cliente, proveedor, almacén, usuario de negocio, promoción, impuesto, anuncio y horario:

- Columnas `deletedAt` (instantáneo, nulo si está vigente) y `deletedBy`.
- La consulta por defecto excluye `deletedAt IS NULL` (`@SQLRestriction` o especificación). Un caso de uso de auditoría puede pedir los dados de baja.
- La operación se llama dar de baja o archivar. La UI dice «Dar de baja», no «Eliminar», y advierte que el histórico se conserva.
- La unicidad de un código (SKU, documento) es un índice parcial `WHERE deleted_at IS NULL`, para poder reutilizar el código tras la baja.
- Dar de baja un agregado marca la raíz. Los hijos no se borran en cascada física.

## Libros

Movimiento de inventario, asiento, cuota, cobro, venta, orden y devolución no se ocultan.

- No llevan baja lógica que los saque del libro.
- La anulación crea un documento o estado de reverso dentro del agregado (contra-asiento, movimiento compensatorio, estado `CANCELADA`).
- Las líneas del libro siguen consultables.

```java
// Mal
productRepository.deleteById(id);

// Bien
product.retire(actor, clock.instant());
productRepository.save(product);
```
````

## architecture-contexts.mdc

````md
---
description: Límites de bounded contexts y contratos entre servicios
globs: "**/*.java"
alwaysApply: false
---

# Contextos

Cada modelo vive en un solo contexto. Un concepto con dos entidades en dos servicios es un error de diseño.

| Contexto | Posee | No posee |
|---|---|---|
| Identidad | Credencial, rol, sesión | `supplierId`, ficha comercial, dirección de cliente |
| Catálogo | Producto vendible, marca, categoría, atributo, precio de lista | Cantidad física, proveedor |
| Inventario | Lote, almacén, movimiento, umbral, alerta de stock | Precio de venta, orden de compra |
| Abastecimiento | Proveedor, cotización, orden de compra, recepción | Stock; la recepción emite un hecho, inventario lo aplica |
| Pedido | Carrito confirmado, checkout, estado del pedido ecommerce | Venta fiscal, asiento |
| Ventas | Venta, detalle, promoción aplicada, devolución, comprobante | Stock, diario contable |
| Cobranza | Cuenta por cobrar, cuota, cobro | Cálculo del IGV de la venta |
| Tienda | Horario, anuncio, cierre extraordinario | Copias en inventario y en ventas |
| Contabilidad | Asiento, línea, plan de cuentas | Se dispara por un hecho, no dentro de `SaleService` |

- Entre contextos solo circula un id y un contrato publicado, o un evento (`GoodsReceived`, `SaleConfirmed`, `ReturnConfirmed`). Sin `@ManyToOne` cruzando bases.
- El contexto consumidor guarda una proyección local de solo lectura. No confía en el subtotal que calcula el navegador.
- El controlador no es el caso de uso: traduce HTTP y llama a la aplicación. No devuelve la entidad JPA.
- Identidad no importa paquetes `inventory` ni `store`. El paquete raíz del servicio coincide con su contexto.
- Feign, URL y puerto viven en configuración. Un fallo de otro contexto se propaga como error de aplicación, no como lista vacía.
````

## architecture-domain.mdc

````md
---
description: Modelo táctico DDD, agregados e invariantes de Nomos
globs: "**/*.java"
alwaysApply: false
---

# Modelo táctico

La regla de negocio vive en el agregado. JPA es el adaptador y no sale del paquete de persistencia.

- Un agregado expone métodos (`confirm`, `receive`, `cancel`, `applyPayment`). Sin setters públicos para cantidad, total, precio o estado.
- Prohibido Lombok `@Data` en entidades y agregados. Igualdad por id de dominio.
- `Money` es un value object con escala 2 y moneda. Prohibido `Double` para precio, costo, impuesto, cuota o total.
- El estado es un enum. La transición válida está dentro del agregado. Prohibido `String status` y `setStatus` desde el controlador.
- El caso de uso depende de puertos. No importa clases internas del controlador.

Invariantes que el código debe cerrar:

- El total de la venta se calcula con cantidad, precio de catálogo o proyección, tasa e promoción. El subtotal del cliente se ignora.
- El detalle de venta solo se agrega por la raíz `Sale`. No hay alta ni baja de líneas por un repositorio de detalle.
- La cantidad de un lote solo cambia al registrar un `InventoryMovement`. Prohibido un `PUT` que escriba `quantity`. Si hay varios lotes, el movimiento nombra el lote; prohibido `findFirst()`.
- Completar una orden de compra no es cambiar un enum: la recepción crea el hecho que inventario convierte en entrada.
- Confirmar una venta reserva o descuenta stock. Confirmar una devolución repone stock y ajusta cobranza. Anular una venta revierte asiento y stock con documentos compensatorios.
- `AccountsReceivable.getPaidAmount` excluye cobros en estado `CANCELLED`, nunca un texto suelto.

```java
// Mal: el controlador muta el estado y la cantidad
item.setQuantity(item.getQuantity() + delta);
order.setStatus(OrderStatus.COMPLETO);

// Bien
inventory.register(Movement.inbound(lotId, qty, goodsReceived));
purchaseOrder.receive(receipt);
```
````

## erp-ui-style.mdc

````md
---
description: Composición visual del ERP. El color solo vive en tokens, no en las pantallas
globs: nomos-inventory-system-frontend/**/*.{tsx,css}
alwaysApply: false
---

# Estilo del ERP

Replica la composición actual. El color no se elige en el componente: solo en variables HSL de `client/global.css` (`:root` y `.dark`). En TSX se usan roles (`bg-primary`, `text-muted-foreground`, `bg-card`, `border-border`) o un rol de estado nuevo definido ahí.

## Escala

- Fuente: Inter 400, 600, 700, 800.
- Radio base `--radius: 0.5rem`. Panel `rounded-lg`. Diálogo `rounded-xl`. Pastilla de marca `h-9 w-9 rounded-lg`.
- Shell: `h-screen overflow-hidden`. Columna lateral `280px` desde `lg`; bajo `lg` queda oculta. Cabecera `h-16` con borde inferior y `backdrop-blur`. Solo `<main>` hace scroll (`p-4 md:p-6`).
- Página: `p-6 space-y-6`. Título `text-3xl font-bold`. Sección en card: título `text-2xl font-bold` con icono Lucide `h-6 w-6`.
- Huecos: `gap-3` icono y texto, `gap-4` acciones de barra, `space-y-2` ítems del menú (`text-sm`).
- Iconos: `h-4 w-4` en tabla y búsqueda, `h-5 w-5` en navegación y botón, `h-6 w-6` en título de sección.

## Piezas

- Barra: título a la izquierda; a la derecha búsqueda (`max-w-xs`, icono `absolute left-3`, input `pl-9`), acción secundaria `outline` y acción primaria con icono más texto y `shadow-md`.
- Panel de datos: superficie `bg-card`, `rounded-lg shadow-xl overflow-hidden`. Cabecera de tabla en superficie muted. Fila con `transition-colors duration-150`. Identificador `font-medium`. Importe `font-bold text-right`. Acciones de fila: botón `ghost` de icono.
- Estado: `Badge` sin borde, variante semántica (`success`, `warning`, `danger`, `info`, `neutral`). Si falta la variante, se agrega el token; no se pinta `bg-emerald-600` ni `bg-blue-600` en la página.
- Carga: fila centrada, `Loader2` `h-8 w-8 animate-spin` y texto `ml-3`. Vacío: `text-center py-10 text-muted-foreground`.
- Confirmación: overlay a pantalla completa con `backdrop-blur-sm`, panel `max-w-sm w-full p-6 shadow-2xl`, cabecera con `border-b`, acciones alineadas al final. Para dar de baja se usa el rol `destructive`.
- Login: desde `lg`, dos mitades. Hero con título `text-5xl font-bold` y subtítulo `text-lg` al 80 % de opacidad. Tarjeta `max-w-md`, contenido `p-8`, título `text-3xl`.
- Componentes de `client/components/ui` (Button, Table, Card, Input, Dialog, Badge) antes que un `div` modal propio.
- Movimiento solo de color en 150 ms, más el spinner. Sin animación decorativa.
- Cada superficie nueva tiene par en modo oscuro mediante el mismo token, no mediante una clase `dark:bg-gray-800` suelta.
````

## static-work.mdc

````md
---
description: Trabajar en estático, sin navegador ni builds
alwaysApply: true
---

# Trabajo estático

No ejecutes el navegador ni herramientas de browser (navegar, snapshot, screenshot, click, CDP). No abras la app para comprobar una pantalla.

No lances builds ni servidores: `npm run build`, `npm run dev`, `mvn package`, `mvn spring-boot:run`, `gradle build`, `vite build`, ni un contenedor para ver el sistema. El usuario compila y levanta el proyecto a mano.

Resuelve en estático: lee el código, los tipos y la configuración, y corrige ahí. Si hace falta una comprobación de runtime, dilo en el resumen y deja el comando para que lo ejecute el usuario.

Únicamente cuando yo te total libertad de uso de comandos puedes usarlos
````
