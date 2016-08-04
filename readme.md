## About

Plugin assist in creation classes/structures and detection virtual tables. Best to use with [Class Informer](0) plugin, because it helps to automatically get original classes names

# Features

### Structure Graph

Shows relationship between structures.
![img][structure_graph]

Usage:

1. Open Local Types
2. Select interesting structures and right click -> "Show Graph" 
3. Plugin creates a graph of all structures that have relationship with selected items.
4. Double clicking on node recalculates graph for it
5. Every node have a hint message that shows C-like typedef

### Structure Builder

### Currently recognized access to fields

* var - variable
* obj - any object, including Virtual Table, that will be handled specially
* x - offset
* TYPE - char, _BYTE, int, _DWORD, float, double

##### x32
| Variable type | Situation | Type | Offset |
| --- | --- | --- | --- |
| `int` | `*(_DWORD *) v = var` | `typeof(var)` | 0 |
| | `*(_DWORD *) v = obj` | `typeof(obj)` | 0 |
| | `*(_DWORD *) v = &obj` | `typeof(obj)` | 0 |
| | `*(TYPE *)(v + x) = num` | `TYPE` | x |
| | `*(_DWORD *)(v + x) = var` | `typeof(var)` | x |
| | `*(_DWORD *)(v + x) = obj` | `typeof(obj)` | x |

#### x64
| Variable type | Situation | Type | Offset |
| --- | --- | --- | --- |
| `__int64`, `signed __int64` | `*(_QWORD *) v = var` | `typeof(var)` | 0 |
| | `*(_QWORD *) v = obj` | `typeof(obj)` | 0 |
| | `*(_QWORD *) v = &obj` | `typeof(obj)` | 0 |
| | `*(TYPE *)(v + x) = num` | `TYPE` | x |
| | `*(_QWORD *)(v + x) = var` | `typeof(var)` | x |
| | `*(_QWORD *)(v + x) = obj` | `typeof(obj)` | x |

[0]: https://sourceforge.net/projects/classinformer/
[structure_graph]: https://rg-git/traineeship/HexRaysPyTools/tree/master/Img/structure_builder.jpg