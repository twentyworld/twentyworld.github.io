# 数据库的定义

数据库：物理操作文件系统或其他形式文件类型的集合；

实例：MySQL 数据库由后台线程以及一个共享内存区组成；

在 MySQL 中，实例和数据库往往都是一一对应的，而我们也无法直接操作数据库，而是要通过数据库实例来操作数据库文件，可以理解为数据库实例是数据库为上层提供的一个专门用于操作的接口。

在 Unix 上，启动一个 MySQL 实例往往会产生两个进程，mysqld 就是真正的数据库服务守护进程，而 mysqld_safe 是一个用于检查和设置 mysqld 启动的控制程序，它负责监控 MySQL 进程的执行，当 mysqld 发生错误时，mysqld_safe 会对其状态进行检查并在合适的条件下重启。

# MySQL 的架构

![](image/MySQL-8.png)


![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-9.png)

# 索引
索引是数据库中非常非常重要的概念，它是存储引擎能够快速定位记录的秘密武器，对于提升数据库的性能、减轻数据库服务器的负担有着非常重要的作用；索引优化是对查询性能优化的最有效手段，它能够轻松地将查询的性能提高几个数量级。


**为什么使用数据索引能提高效率？**
1. 数据索引的存储是有序的
2. 在有序的情况下，通过索引查询一个数据是无需遍历索引记录的
3. 极端情况下，数据索引的查询效率为二分法查询效率，趋近于 log2(N)

## B+树索引和哈希索引的区别
B+树是一个平衡的多叉树，从根节点到每个叶子节点的高度差值不超过1，而且同层级的节点间有指针相互链接，是有序的

![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-1.jpg)

哈希索引就是采用一定的哈希算法，把键值换算成新的哈希值，检索时不需要类似B+树那样从根节点到叶子节点逐级查找，只需一次哈希算法即可,是无序的

![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-2.jpg)

**哈希索引的优势：**

1. 等值查询。哈希索引具有绝对优势（前提是：没有大量重复键值，如果大量重复键值时，哈希索引的效率很低，因为存在所谓的哈希碰撞问题。）

**哈希索引不适用的场景：**

1. 不支持范围查询
2. 不支持索引完成排序
3. 不支持联合索引的最左前缀匹配规则


通常，B+树索引结构适用于绝大多数场景，像下面这种场景用哈希索引才更有优势：

在HEAP表中，如果存储的数据重复度很低（也就是说基数很大），对该列数据以等值查询为主，没有范围查询、没有排序的时候，特别适合采用哈希索引，例如这种SQL：
```mysql
select id,name from table where name='李明'; — 仅等值查询
```
而常用的InnoDB引擎中默认使用的是B+树索引，它会实时监控表上索引的使用情况，如果认为建立哈希索引可以提高查询效率，则自动在内存中的“自适应哈希索引缓冲区”建立哈希索引（在InnoDB中默认开启自适应哈希索引），通过观察搜索模式，MySQL会利用index key的前缀建立哈希索引，如果一个表几乎大部分都在缓冲池中，那么建立一个哈希索引能够加快等值查询。

注意：在某些工作负载下，通过哈希索引查找带来的性能提升远大于额外的监控索引搜索情况和保持这个哈希表结构所带来的开销。但某些时候，在负载高的情况下，自适应哈希索引中添加的read/write锁也会带来竞争，比如高并发的join操作。like操作和%的通配符操作也不适用于自适应哈希索引，可能要关闭自适应哈希索引。



## B树和B+树的区别
1. B树，每个节点都存储key和data，所有节点组成这棵树，并且叶子节点指针为nul，叶子结点不包含任何关键字信息。
  ![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-3.jpg)
2. B+树，所有的叶子结点中包含了全部关键字的信息，及指向含有这些关键字记录的指针，且叶子结点本身依关键字的大小自小而大的顺序链接，所有的非终端结点可以看成是索引部分，结点中仅含有其子树根结点中最大（或最小）关键字。 (而B 树的非终节点也包含需要查找的有效信息)

![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-4.jpg)


**为什么说B+比B树更适合实际应用中操作系统的文件索引和数据库索引？**

1、 B+的磁盘读写代价更低

B+的内部结点并没有指向关键字具体信息的指针。因此其内部结点相对B树更小。如果把所有同一内部结点的关键字存放在同一盘块中，那么盘块所能容纳的关键字数量也越多。一次性读入内存中的需要查找的关键字也就越多。相对来说IO读写次数也就降低了。

2、 B+-tree的查询效率更加稳定

由于非终结点并不是最终指向文件内容的结点，而只是叶子结点中关键字的索引。所以任何关键字的查找必须走一条从根结点到叶子结点的路。所有关键字查询的路径长度相同，导致每一个数据的查询效率相当。


## 聚集索引和辅助索引
数据库中的 B+ 树索引可以分为聚集索引（clustered index）和辅助索引（secondary index），它们之间的最大区别就是，聚集索引中存放着一条行记录的全部信息，而辅助索引中只包含索引列和一个用于查找对应行记录的『书签』。

### 聚集索引
聚集索引：指索引项的排序方式和表中数据记录排序方式一致的索引，每张表只能有一个聚集索引，聚集索引的叶子节点存储了整个行数据。

解释：什么叫索引项的排序方式和表中数据记录排序方式一致呢？

我们把一本字典看做是数据库的表，那么字典的拼音目录就是聚集索引，它按照A-Z排列。实际存储的字也是按A-Z排列的。这就是索引项的排序方式和表中数据记录排序方式一致。


对于Innodb，主键毫无疑问是一个聚集索引。但是当一个表没有主键，或者没有一个索引，Innodb会如何处理呢。请看如下规则:
1. 如果一个主键被定义了，那么这个主键就是作为聚集索引。
2. 如果没有主键被定义，那么该表的第一个唯一非空索引被作为聚集索引。
3. 如果没有主键也没有合适的唯一索引，那么innodb内部会生成一个隐藏的主键作为聚集索引，这个隐藏的主键是一个6个字节的列，该列的值会随着数据的插入自增。

![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-6.png)
​    
### 辅助索引
辅助索引：辅助索引中索引的逻辑顺序与磁盘上行的物理存储顺序不同，一个表中可以拥有多个非聚集索引。叶子节点并不包含行记录的全部数据。叶子节点除了包含键值以外，还存储了一个指向改行数据的聚集索引建的书签。

辅助索引可以理解成字典按偏旁去查字。

辅助索引的存在并不会影响聚集索引，因为聚集索引构成的 B+ 树是数据实际存储的形式，而辅助索引只用于加速数据的查找，所以一张表上往往有多个辅助索引以此来提升数据库的性能。

一张表一定包含一个聚集索引构成的 B+ 树以及若干辅助索引的构成的 B+ 树。

通过辅助索引查找到对应的主键，最后在聚集索引中使用主键获取对应的行记录，这也是通常情况下行记录的查找方式。

![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-7.png)

## mysql联合索引
1. 联合索引是两个或更多个列上的索引。对于联合索引:Mysql从左到右的使用索引中的字段，一个查询可以只使用索引中的一部份，但只能是最左侧部分。例如索引是key index (a,b,c). 可以支持a   、    a,b   、  a,b,c 3种组合进行查找，但不支持 b,c进行查找 .当最左侧字段是常量引用时，索引就十分有效。
2. 利用索引中的附加列，您可以缩小搜索的范围，但使用一个具有两列的索引 不同于使用两个单独的索引。复合索引的结构与电话簿类似，人名由姓和名构成，电话簿首先按姓氏对进行排序，然后按名字对有相同姓氏的人进行排序。如果您知 道姓，电话簿将非常有用；如果您知道姓和名，电话簿则更为有用，但如果您只知道名不姓，电话簿将没有用处。

## 什么情况下应不建或少建索引
1. 表记录太少
2. 经常插入、删除、修改的表
3. 数据重复且分布平均的表字段，假如一个表有10万行记录，有一个字段A只有T和F两种值，且每个值的分布概率大约为50%，那么对这种表A字段建索引一般不会提高数据库的查询速度。
4. 经常和主字段一块查询但主字段索引值比较多的表字段

## 导致索引失效的一些情况
1．隐式转换导致索引失效.这一点应当引起重视.也是开发中经常会犯的错误.

 由于表的字段tu_mdn定义为varchar2(20),但在查询时把该字段作为number类型以where条件传给Oracle,这样会导致索引失效.
 错误的例子：select * from test where tu_mdn=13333333333;
 正确的例子：select * from test where tu_mdn='13333333333';

2. 对索引列进行运算导致索引失效,我所指的对索引列进行运算包括(+，-，*，/，! 等)

 错误的例子：select * from test where id-1=9;
 正确的例子：select * from test where id=10;


3. 以下使用会使索引失效，应避免使用；

a. 使用 <> 、not in 、not exist、!=
b. like "%_" 百分号在前（可采用在建立索引时用reverse(columnName)这种方法处理）
c. 单独引用复合索引里非第一位置的索引列.应总是使用索引的第一个列，如果索引是建立在多个列上, 只有在它的第一个列被where子句引用时，优化器才会选择使用该索引。
d. 字符型字段为数字时在where条件里不添加引号.
e. 当变量采用的是times变量，而表的字段采用的是date变量时.或相反情况。

4. 不要将空的变量值直接与比较运算符（符号）比较。

如果变量可能为空，应使用 IS NULL 或 IS NOT NULL 进行比较，或者使用 ISNULL 函数。

5. 不要在 SQL 代码中使用双引号。

因为字符常量使用单引号。如果没有必要限定对象名称，可以使用（非 ANSI SQL 标准）括号将名称括起来。

6. 将索引所在表空间和数据所在表空间分别设于不同的磁盘chunk上，有助于提高索引查询的效率。


## key和index的区别
1. key 是数据库的物理结构，它包含两层意义和作用，一是约束（偏重于约束和规范数据库的结构完整性），二是索引（辅助查询用的）。包括primary key, unique key, foreign key 等
2. index是数据库的物理结构，它只是辅助查询的，它创建时会在另外的表空间（mysql中的innodb表空间）以一个类似目录的结构存储。索引要分类的话，分为前缀索引、全文本索引等；



# 锁
锁的种类一般分为乐观锁和悲观锁两种，InnoDB 存储引擎中使用的就是悲观锁，而按照锁的粒度划分，也可以分成行锁和表锁.

## 行锁
### 优点
1. 当在许多线程中访问不同的行时只存在少量锁定冲突。
2. 回滚时只有少量的更改
3. 可以长时间锁定单一的行。
### 缺点
1. 比页级或表级锁定占用更多的内存。
2. 当在表的大部分中使用时，比页级或表级锁定速度慢，因为你必须获取更多的锁。
3. 如果你在大部分数据上经常进行GROUP BY操作或者必须经常扫描整个表，比其它锁定明显慢很多。
4. 用高级别锁定，通过支持不同的类型锁定，你也可以很容易地调节应用程序，因为其锁成本小于行级锁定。

## 锁的算法
三种锁的算法：Record Lock、Gap Lock 和 Next-Key Lock
### Record Lock
记录锁（Record Lock）是加到索引记录上的锁，假设我们存在下面的一张表 users：
```java
  CREATE TABLE users(
        id INT NOT NULL AUTO_INCREMENT,
        last_name VARCHAR(255) NOT NULL,
        first_name VARCHAR(255),
        age INT,
        PRIMARY KEY(id),
        KEY(last_name),
        KEY(age)
    );
```
如果我们使用 id 或者 last_name 作为 SQL 中 WHERE 语句的过滤条件，那么 InnoDB 就可以通过索引建立的 B+ 树找到行记录并添加索引，但是如果使用 first_name 作为过滤条件时，由于 InnoDB 不知道待修改的记录具体存放的位置，也无法对将要修改哪条记录提前做出判断就会锁定整个表。
​    
### Gap Lock
记录锁是在存储引擎中最为常见的锁，除了记录锁之外，InnoDB 中还存在间隙锁（Gap Lock），间隙锁是对索引记录中的一段连续区域的锁；当使用类似 SELECT * FROM users WHERE id BETWEEN 10 AND 20 FOR UPDATE; 的 SQL 语句时，就会阻止其他事务向表中插入 id = 15 的记录，因为整个范围都被间隙锁锁定了。
​    
间隙锁是存储引擎对于性能和并发做出的权衡，并且只用于某些事务隔离级别。
​    
虽然间隙锁中也分为共享锁和互斥锁，不过它们之间并不是互斥的，也就是不同的事务可以同时持有一段相同范围的共享锁和互斥锁，它唯一阻止的就是其他事务向这个范围中添加新的记录。

Gap Lock的作用是为了阻止多个事务将记录插入到同一个范围内，这样会导致幻读的产生。用户可以通过以下两种服务显式地关闭Gap Lock。
1. 将事务的隔离级别设置为READ COMMITTED
2. 将参数innodb_locks_unsafe_for_binlog设置为1


除了外键约束和唯一性检查需要的Gap Lock，其余情况仅使用Record Lock进行锁定。这样做破坏了事务的隔离性，并且对于replication会导致主动数据的不一致。
​    
### Next-Key Lock
Next-Key Lock是结合了Gap Lock和Record Lock的一种锁定算法,其设置的目的是为了解决幻读问题。

当查询的索引含有唯一属性的时候，InnoDB存储引擎会对Next-Key Lock进行优化，将其降为Record Lock，即仅仅锁住索引本身，而不是范围，从而提高并发效率。

对于唯一值的锁定，Next-Key Lock降级为Record Lock仅存在于查询所有的唯一索引列。若唯一索引由多个列组成，而查询仅是查找多个唯一索引列中的其中一个，那么查询其实是range类型，而不是point类型的查询。此时InnoDB存储引擎依然使用Next-Key Lock进行锁定。

## 锁选择

下面我们针对大部分的SQL类型分析是如何加锁的，假设事务隔离级别为可重复读

**select .. from**  

不加任何类型的锁

**select...from lock in share mode**

在扫描到的任何索引记录上加共享的（shared）next-key lock，还有主键聚集索引加排它锁 

**select..from for update**

在扫描到的任何索引记录上加排它的next-key lock，还有主键聚集索引加排它锁 

**update..where   delete from..where**

在扫描到的任何索引记录上加next-key lock，还有主键聚集索引加排它锁 

**insert into..**

简单的insert会在insert的行对应的索引记录上加一个排它锁，这是一个record lock，并没有gap，所以并不会阻塞其他session在gap间隙里插入记录。不过在insert操作之前，还会加一种锁，官方文档称它为insertion intention gap lock，也就是意向的gap锁。这个意向gap锁的作用就是预示着当多事务并发插入相同的gap空隙时，只要插入的记录不是gap间隙中的相同位置，则无需等待其他session就可完成，这样就使得insert操作无须加真正的gap lock。想象一下，如果一个表有一个索引idx_test，表中有记录1和8，那么每个事务都可以在2和7之间插入任何记录，只会对当前插入的记录加record lock，并不会阻塞其他session插入与自己不同的记录，因为他们并没有任何冲突。

# MySQL分区
## 什么是分区？
表分区，是指根据一定规则，将数据库中的一张表分解成多个更小的，容易管理的部分。从逻辑上看，只有一张表，但是底层却是由多个物理分区组成。

## 分区与分表的区别
分表：指的是通过一定规则，将一张表分解成多张不同的表。比如将用户订单记录根据时间成多个表。 

分表与分区的区别在于：分区从逻辑上来讲只有一张表，而分表则是将一张表分解成多张表。



## 使用场景

1. 表非常大，无法全部存在内存，或者只在表的最后有热点数据，其他都是历史数据。
2. 分区表的数据更易维护，可以对独立的分区进行独立的操作。
3. 分区表的数据可以分布在不同的机器上，从而高效适用资源。
4. 可以使用分区表来避免某些特殊的瓶颈
5. 可以备份和恢复独立的分区

## 限制
1. 一个表最多只能有1024个分区 
2. MySQL5.1中，分区表达式必须是整数，或者返回整数的表达式。在MySQL5.5中提供了非整数表达式分区的支持。 
3. 如果分区字段中有主键或者唯一索引的列，那么多有主键列和唯一索引列都必须包含进来。即：分区字段要么不包含主键或者索引列，要么包含全部主键和索引列。
4. 分区表中无法使用外键约束 
5. 需要对现有表的结构进行修改
6. 所有分区都必须使用相同的存储引擎
7. 分区函数中可以使用的函数和表达式会有一些限制
8. 某些存储引擎不支持分区
9. 对于MyISAM的分区表，不能使用load index into cache
10. 对于MyISAM表，使用分区表时需要打开更多的文件描述符

## 如何判断当前MySQL是否支持分区？
命令：show variables like '%partition%' 运行结果:

mysql> show variables like '%partition%';
```mysql
+-------------------+-------+
| Variable_name     | Value |
+-------------------+-------+
| have_partitioning | YES   |
+-------------------+-------+
```
1 row in set (0.00 sec)
have_partintioning 的值为YES，表示支持分区。

## MySQL支持的分区类型有哪些？
1. RANGE分区： 这种模式允许将数据划分不同范围。例如可以将一个表通过年份划分成若干个分区
2. LIST分区： 这种模式允许系统通过预定义的列表的值来对数据进行分割。按照List中的值分区，与RANGE的区别是，range分区的区间范围值是连续的。 
3. HASH分区 ：这中模式允许通过对表的一个或多个列的Hash Key进行计算，最后通过这个Hash码不同数值对应的数据区域进行分区。例如可以建立一个对表主键进行分区的表。
4. KEY分区 ：上面Hash模式的一种延伸，这里的Hash Key是MySQL系统产生的。

# 日志模块
## redo log（重做日志）
如果每一次的更新操作都需要写进磁盘，然后磁盘也要找到对应的那条记录，然后再更新，整个过程 IO 成本、查找成本都很高。为了解决这个问题，可以使用 WAL 技术，WAL 的全称是 Write-Ahead Logging，它的关键点就是先写日志，再写磁盘

具体来说，当有一条记录需要更新的时候，InnoDB 引擎就会先把记录写到 redo log里面，并更新内存，这个时候更新就算完成了。同时，InnoDB 引擎会在适当的时候，将这个操作记录更新到磁盘里面，而这个更新往往是在系统比较空闲的时候做。

InnoDB 的 redo log 是固定大小的，比如可以配置为一组 4 个文件，每个文件的大小是 1GB，也就是总共就可以记录 4GB 的操作。从头开始写，写到末尾就又回到开头循环写。


## binlog（归档日志）
MySQL 整体来看，其实就有两块：一块是 Server 层，它主要做的是 MySQL 功能层面的事情；还有一块是引擎层，负责存储相关的具体事宜。 redo log 是 InnoDB 引擎特有的日志，而 Server 层也有自己的日志，称为 binlog（归档日志）

作用：
1. 可以用来查看数据库的变更历史（具体的时间点所有的SQL操作）
2. 数据库增量备份和恢复（增量备份和基于时间点的恢复）
3. MySQL的复制（主主数据库的复制、主从数据库的复制）

## 两种日志区别
1. redo log 是 InnoDB 引擎特有的；binlog 是 MySQL 的 Server 层实现的，所有引擎都可以使用。
2. redo log 是物理日志，记录的是“在某个数据页上做了什么修改”；binlog 是逻辑日志，记录的是这个语句的原始逻辑，比如“给 ID=2 这一行的 c 字段加 1 ”。
3. redo log 是循环写的，空间固定会用完；binlog 是可以追加写入的。“追加写”是指 binlog 文件写到一定大小后会切换到下一个，并不会覆盖以前的日志。

# 四种隔离级别

1. Serializable (串行化)：可避免脏读、不可重复读、幻读的发生。
2. Repeatable read (可重复读)：可避免脏读、不可重复读的发生。
3. Read committed (读已提交)：可避免脏读的发生。
4. Read uncommitted (读未提交)：最低级别，任何情况都无法保证。

# 对于脏读，不可重复读，幻读的理解

## 脏读
 针对未提交数据

 如果一个事务中对数据进行了更新，但事务还没有提交，另一个事务可以“看到”该事务没有提交的更新结果，这样造成的问题就是，如果第一个事务回滚，那么，第二个事务在此之前所“看到”的数据就是一笔脏数据。

## 不可重复读
针对其他提交前后，读取数据本身的对比

不可重复读取是指同一个事务在整个事务过程中对同一笔数据进行读取，每次读取结果都不同。如果事务1在事务2的更新操作之前读取一次数据，在事务2的更新操作之后再读取同一笔数据一次，两次结果是不同的，所以，Read Uncommitted也无法避免不可重复读取的问题。

## 幻读
针对其他提交前后，读取数据条数的对比

幻读是指同样一笔查询在整个事务过程中多次执行后，查询所得的结果集是不一样的。幻读针对的是多笔记录。在Read Uncommitted隔离级别下， 不管事务2的插入操作是否提交，事务1在插入操作之前和之后执行相同的查询，取得的结果集是不同的，所以，Read Uncommitted同样无法避免幻读的问题。

## 不可重复读和幻读区别
1. 不可重复读的重点是修改: 同样的条件, 你读取过的数据, 再次读取出来发现值不一样了
2. 幻读的重点在于新增或者删除 (数据条数变化)，同样的条件， 第1次和第2次读出来的记录数不一样

# 关于MVVC
MySQL InnoDB存储引擎，实现的是基于多版本的并发控制协议——MVCC (Multi-Version Concurrency Control) (注：与MVCC相对的，是基于锁的并发控制，Lock-Based Concurrency Control)。MVCC最大的好处：读不加锁，读写不冲突。在读多写少的OLTP应用中，读写不冲突是非常重要的，极大的增加了系统的并发性能，现阶段几乎所有的RDBMS，都支持了MVCC。

1. LBCC：Lock-Based Concurrency Control，基于锁的并发控制。
2. MVCC：Multi-Version Concurrency Control，基于多版本的并发控制协议。纯粹基于锁的并发机制并发量低，MVCC是在基于锁的并发控制上的改进，主要是在读操作上提高了并发量。

在MVCC并发控制中，读操作可以分成两类：

1. 快照读 (snapshot read)：读取的是记录的可见版本 (有可能是历史版本)，不用加锁（共享读锁s锁也不加，所以不会阻塞其他事务的写）。
2. 当前读 (current read)：读取的是记录的最新版本，并且，当前读返回的记录，都会加上锁，保证其他事务不会再并发修改这条记录。





# 存储过程

简单的说，就是一组SQL语句集，功能强大，可以实现一些比较复杂的逻辑功能，类似于JAVA语言中的方法；

ps:存储过程跟触发器有点类似，都是一组SQL集，但是存储过程是主动调用的，且功能比触发器更加强大，触发器是某件事触发后自动调用；

有哪些特性
1. 有输入输出参数，可以声明变量，有if/else, case,while等控制语句，通过编写存储过程，可以实现复杂的逻辑功能；
2. 函数的普遍特性：模块化，封装，代码复用；
3. 速度快，只有首次执行需经过编译和优化步骤，后续被调用可以直接执行，省去以上步骤；







# Mysql存储引擎

## MyISAM和InnoDB的区别

1. InnoDB支持事务，MyISAM不支持，对于InnoDB每一条SQL语言都默认封装成事务，自动提交，这样会影响速度，所以最好把多条SQL语言放在begin和commit之间，组成一个事务；  

2. InnoDB支持外键，而MyISAM不支持。对一个包含外键的InnoDB表转为MYISAM会失败；  

3. InnoDB是聚集索引，数据文件是和索引绑在一起的，必须要有主键，通过主键索引效率很高。但是辅助索引需要两次查询，先查询到主键，然后再通过主键查询到数据。因此，主键不应该过大，因为主键太大，其他索引也都会很大。而MyISAM是非聚集索引，数据文件是分离的，索引保存的是数据文件的指针。主键索引和辅助索引是独立的。 

4. InnoDB不保存表的具体行数，执行select count(*) from table时需要全表扫描。而MyISAM用一个变量保存了整个表的行数，执行上述语句时只需要读出该变量即可，速度很快；  

5. Innodb不支持全文索引，而MyISAM支持全文索引，查询效率上MyISAM要高；   



## 如何选择

1. 是否要支持事务，如果要请选择innodb，如果不需要可以考虑MyISAM；

2. 如果表中绝大多数都只是读查询，可以考虑MyISAM，如果既有读写也挺频繁，请使用InnoDB。

3. 系统奔溃后，MyISAM恢复起来更困难，能否接受；

4. MySQL5.5版本开始Innodb已经成为Mysql的默认引擎(之前是MyISAM)，说明其优势是有目共睹的，如果你不知道用什么，那就用InnoDB，至少不会差。



# mysql主从同步

主从同步使得数据可以从一个数据库服务器复制到其他服务器上，在复制数据时，一个服务器充当主服务器（master），其余的服务器充当从服务器（slave）。因为复制是异步进行的，所以从服务器不需要一直连接着主服务器，从服务器甚至可以通过拨号断断续续地连接主服务器。通过配置文件，可以指定复制所有的数据库，某个数据库，甚至是某个数据库上的某个表。

## 使用主从同步的好处

1. 通过增加从服务器来提高数据库的性能，在主服务器上执行写入和更新，在从服务器上向外提供读功能，可以动态地调整从服务器的数量，从而调整整个数据库的性能。
2. 提高数据安全-因为数据已复制到从服务器，从服务器可以终止复制进程，所以，可以在从服务器上备份而不破坏主服务器相应数据
3. 在主服务器上生成实时数据，而在从服务器上分析这些数据，从而提高主服务器的性能

## 主从复制原理
>1. 主库需要一个线程叫做I/O线程
>2. 从库需要两个线程完成，一个叫做I/O线程，一个叫做sql线程

![](https://github.com/zaiyunduan123/Java-Interview/blob/master/image/MySQL-5.jpg)

1. 主库必须要开启binlog日志才能完成主从同步，当用户请求到主的库里面，会将增删改的东西记录到binlog日志里面.
2. 主从复制是从库去找主库的，建立时，我们在从库上使用change master指定master的ip，端口，二进制文件名称，pos，master的密码等信息。并在从库上开启start  slave就会开启同步.
3. 开启同步后，先是从向主发起请求。然后主库进行验证从库是否正常，验证之后，主库就会给从库按照信息发送日志.
4. 从库上存放日志的地方叫做中继日志（relay log），其实从库里面还有一个master info信息，这个里面记录的是change master的信息，每一次取日志回来都会对从库的master  info信息进行更新，接下来从库根据master  info的binlog信息去主库在取跟新的binlog信息，

从库的io线程会实时依据master.info信息的去主库的binlog日志里面读取更新的内容，将更新的内容取回到自己的中继日志中，同时会更新master.info信息，此时sql线程实时会从中继日志中读取并执行里面的sql语句。


# MySQL事务原理
ACID是通过redo 和 undo 日志文件实现的，不管是redo还是undo文件都会有一个缓存我们称之为redo_buf和undo_buf。同样，数据库文件也会有缓存称之为data_buf。

## undo 日志文件
undo记录了数据在事务开始之前的值，当事务执行失败或者ROLLBACK时可以通过undo记录的值来恢复数据。例如 AA和BB的初始值分别为3，5。
```
A 事务开始
B 记录AA=3到undo_buf
C 修改AA=1
D 记录BB=5到undo_buf
E 修改BB=7
F 将undo_buf写到undo(磁盘)
G 将data_buf写到datafile(磁盘)
H 事务提交
```
1. 如果事务在F之前崩溃由于数据还没写入磁盘，所以数据不会被破坏。
2. 如果事务在G之前崩溃或者回滚则可以根据undo恢复到初始状态。 

但是单纯使用undo保证原子性和持久性需要在事务提交之前将数据写到磁盘，浪费大量I/O。

## redo/undo日志文件
引入redo日志记录数据修改后的值，可以避免数据在事务提交之前必须写入到磁盘的需求，减少I/O。
```
A 事务开始
B 记录AA=3到undo_buf
C 修改AA=1 记录redo_buf
D 记录BB=5到undo_buf
E 修改BB=7 记录redo_buf
F 将redo_buf写到redo（磁盘）
G 事务提交
```
通过undo保证事务的原子性，redo保证持久性。 

1. F之前崩溃由于所有数据都在内存，恢复后重新冲磁盘载入之前的数据，数据没有被破坏。 
2. FG之间的崩溃可以使用redo来恢复。 
3. G之前的回滚都可以使用undo来完成。


# 为什么用自增列作为主键
1. 如果我们定义了主键(PRIMARY KEY)，那么InnoDB会选择主键作为聚集索引、如果没有显式定义主键，则InnoDB会选择第一个不包含有NULL值的唯一索引作为主键索引、如果也没有这样的唯一索引，则InnoDB会选择内置6字节长的ROWID作为隐含的聚集索引(ROWID随着行记录的写入而主键递增，这个ROWID不像ORACLE的ROWID那样可引用，是隐含的)。

2. 数据记录本身被存于主索引（一颗B+Tree）的叶子节点上。这就要求同一个叶子节点内（大小为一个内存页或磁盘页）的各条数据记录按主键顺序存放，因此每当有一条新的记录插入时，MySQL会根据其主键将其插入适当的节点和位置，如果页面达到装载因子（InnoDB默认为15/16），则开辟一个新的页（节点）

3. 如果表使用自增主键，那么每次插入新的记录，记录就会顺序添加到当前索引节点的后续位置，当一页写满，就会自动开辟一个新的页

4. 如果使用非自增主键（如果身份证号或学号等），由于每次插入主键的值近似于随机，因此每次新纪录都要被插到现有索引页得中间某个位置，此时MySQL不得不为了将新记录插到合适位置而移动数据，甚至目标页面可能已经被回写到磁盘上而从缓存中清掉，此时又要从磁盘上读回来，这增加了很多开销，同时频繁的移动、分页操作造成了大量的碎片，得到了不够紧凑的索引结构，后续不得不通过OPTIMIZE TABLE来重建表并优化填充页面。


# Join的实现原理

MySQL是只支持一种JOIN算法Nested-Loop Join（嵌套循环链接），他没有其他很多数据库所提供的Hash Join（哈希链接），也没有Sort-Merge Join（合并链接）。

当进行多表连接查询时， 驱动表 的定义为：

1. 指定了联接条件时，满足查询条件的记录行数少的表为驱动表

2. 未指定联接条件时，行数少的表为驱动表

Nested-Loop Join实际上就是是通过驱动表的结果集作为循环基础数据，然后一条一条地通过该结果集中的数据作为过滤条件到下一个表中查询数据，然后合并结果。还细分为三种

1. Simple Nested-Loop Join：从驱动表中取出R1匹配S表所有列，然后R2，R3,直到将R表中的所有数据匹配完，然后合并数据
2. Index Nested-Loop Join：驱动表会根据关联字段的索引进行查找，当在索引上找到了符合的值，再回表进行查询，也就是只有当匹配到索引以后才会进行回表，如果非驱动表的关联键是主键的话，这样来说性能就会非常的高。
3. Block Nested-Loop Join：如果Join的列没有索引，这时MySQL会优先使用Block Nested-Loop Join的算法，Block Nested-Loop Join对比Simple Nested-Loop Join多了一个中间处理的过程，也就是join buffer，使用join buffer将驱动表的查询JOIN相关列都给缓冲到了JOIN BUFFER当中，然后批量与非驱动表进行比较，可以将多次比较合并到一次，降低了非驱动表的访问频率。

## 优化

1. 不推荐用join，让mysql自己决定，mysql查询优化器会自动选择数据量最小的那张表作为驱动表。
2. 因为用left join的时候，左边的是驱动表，考虑到查询效率，能用join就不要用left\right join 使用外连接非常影响查询效率，就算要用也要用数据量最小的表作为驱动表来驱动大表，以此保证：“永远用小结果集驱动大结果集”，尽可能减少JOIN中Nested Loop的循环次数。




# MySQL优化
1. 开启查询缓存，优化查询
2. explain你的select查询，这可以帮你分析你的查询语句或是表结构的性能瓶颈。EXPLAIN 的查询结果还会告诉你你的索引主键被如何利用的，你的数据表是如何被搜索和排序的
3. 当只要一行数据时使用limit 1，MySQL数据库引擎会在找到一条数据后停止搜索，而不是继续往后查少下一条符合记录的数据
4. 为搜索字段建索引
5. 使用 ENUM 而不是 VARCHAR，如果你有一个字段，比如“性别”，“国家”，“民族”，“状态”或“部门”，你知道这些字段的取值是有限而且固定的，那么，你应该使用 ENUM 而不是VARCHAR。
6. Prepared Statements
  Prepared Statements很像存储过程，是一种运行在后台的SQL语句集合，我们可以从使用 prepared statements 获得很多好处，无论是性能问题还是安全问题。Prepared Statements 可以检查一些你绑定好的变量，这样可以保护你的程序不会受到“SQL注入式”攻击
7. 垂直分表
8. 选择正确的存储引擎



针对 Innodb 存储引擎的三大特性有：两次写，自适应哈希索引，插入缓冲；

1. double write（两次写）作用：可以保证页损坏之后，有副本直接可以进行恢复。
2. adaptive hash index（自适应哈希索引）作用：Innodb 存储引擎会监控对表上索引的查找，如果观察到建立哈希索引可以带来速度上的提升，则建立哈希索引。读写速度上也有所提高。
3. insert buffer （插入缓冲）作用：针对普通索引的插入把随机 IO 变成顺序 IO，并合并插入磁盘