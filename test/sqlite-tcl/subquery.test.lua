#!./tcltestrunner.lua

# 2005 January 19
#
# The author disclaims copyright to this source code.  In place of
# a legal notice, here is a blessing:
#
#    May you do good and not evil.
#    May you find forgiveness for yourself and forgive others.
#    May you share freely, never taking more than you give.
#
#*************************************************************************
# This file implements regression tests for SQLite library.  The
# focus of this script is testing correlated subqueries
#
# $Id: subquery.test,v 1.17 2009/01/09 01:12:28 drh Exp $
#

set testdir [file dirname $argv0]
source $testdir/tester.tcl

ifcapable !subquery {
  finish_test
  return
}

do_test subquery-1.1 {
  execsql {
    BEGIN;
    CREATE TABLE t1(a PRIMARY KEY,b);
    INSERT INTO t1 VALUES(1,2);
    INSERT INTO t1 VALUES(3,4);
    INSERT INTO t1 VALUES(5,6);
    INSERT INTO t1 VALUES(7,8);
    CREATE TABLE t2(x PRIMARY KEY,y);
    INSERT INTO t2 VALUES(1,1);
    INSERT INTO t2 VALUES(3,9);
    INSERT INTO t2 VALUES(5,25);
    INSERT INTO t2 VALUES(7,49);
    COMMIT;
  }
  execsql {
    SELECT a, (SELECT y FROM t2 WHERE x=a) FROM t1 WHERE b<8
  }
} {1 1 3 9 5 25}
do_test subquery-1.2 {
  execsql {
    UPDATE t1 SET b=b+(SELECT y FROM t2 WHERE x=a);
    SELECT * FROM t1;
  }
} {1 3 3 13 5 31 7 57}

do_test subquery-1.3 {
  execsql {
    SELECT b FROM t1 WHERE EXISTS(SELECT * FROM t2 WHERE y=a)
  }
} {3}
do_test subquery-1.4 {
  execsql {
    SELECT b FROM t1 WHERE NOT EXISTS(SELECT * FROM t2 WHERE y=a)
  }
} {13 31 57}

# Simple tests to make sure correlated subqueries in WHERE clauses
# are used by the query optimizer correctly.
do_test subquery-1.5 {
  execsql {
    SELECT a, x FROM t1, t2 WHERE t1.a = (SELECT x);
  }
} {1 1 3 3 5 5 7 7}
do_test subquery-1.6 {
  execsql {
    CREATE INDEX i1 ON t1(a);
    SELECT a, x FROM t1, t2 WHERE t1.a = (SELECT x);
  }
} {1 1 3 3 5 5 7 7}
do_test subquery-1.7 {
  execsql {
    SELECT a, x FROM t2, t1 WHERE t1.a = (SELECT x);
  }
} {1 1 3 3 5 5 7 7}

# Try an aggregate in both the subquery and the parent query.
do_test subquery-1.8 {
  execsql {
    SELECT count(*) FROM t1 WHERE a > (SELECT count(*) FROM t2);
  }
} {2}

# Test a correlated subquery disables the "only open the index" optimization.
do_test subquery-1.9.1 {
  execsql {
    SELECT (y*2)>b FROM t1, t2 WHERE a=x;
  }
} {0 1 1 1}
do_test subquery-1.9.2 {
  execsql {
    SELECT a FROM t1 WHERE (SELECT (y*2)>b FROM t2 WHERE a=x); 
  }
} {3 5 7}

# Test that the flattening optimization works with subquery expressions.
do_test subquery-1.10.1 {
  execsql {
    SELECT (SELECT a), b FROM t1;
  }
} {1 3 3 13 5 31 7 57}
do_test subquery-1.10.2 {
  execsql {
    SELECT * FROM (SELECT (SELECT a), b FROM t1);
  }
} {1 3 3 13 5 31 7 57}
do_test subquery-1.10.3 {
  execsql {
    SELECT * FROM (SELECT (SELECT sum(a) FROM t1));
  }
} {16}
do_test subquery-1.10.4 {
  execsql {
    CREATE TABLE t5 (val int, period text PRIMARY KEY);
    INSERT INTO t5 VALUES(5, '2001-3');
    INSERT INTO t5 VALUES(10, '2001-4');
    INSERT INTO t5 VALUES(15, '2002-1');
    INSERT INTO t5 VALUES(5, '2002-2');
    INSERT INTO t5 VALUES(10, '2002-3');
    INSERT INTO t5 VALUES(15, '2002-4');
    INSERT INTO t5 VALUES(10, '2003-1');
    INSERT INTO t5 VALUES(5, '2003-2');
    INSERT INTO t5 VALUES(25, '2003-3');
    INSERT INTO t5 VALUES(5, '2003-4');

    SELECT period, vsum
    FROM (SELECT 
      a.period,
      (select sum(val) from t5 where period between a.period and '2002-4') vsum
      FROM t5 a where a.period between '2002-1' and '2002-4')
    WHERE vsum < 45 ;
  }
} {2002-2 30 2002-3 25 2002-4 15}
do_test subquery-1.10.5 {
  execsql {
    SELECT period, vsum from
      (select a.period,
      (select sum(val) from t5 where period between a.period and '2002-4') vsum
    FROM t5 a where a.period between '2002-1' and '2002-4') 
    WHERE vsum < 45 ;
  }
} {2002-2 30 2002-3 25 2002-4 15}
do_test subquery-1.10.6 {
  execsql {
    DROP TABLE t5;
  }
} {}



#------------------------------------------------------------------
# The following test cases - subquery-2.* - are not logically
# organized. They're here largely because they were failing during
# one stage of development of sub-queries.
#
do_test subquery-2.1 {
  execsql {
    SELECT (SELECT 10);
  }
} {10}
do_test subquery-2.2.1 {
  execsql {
    CREATE TABLE t3(a PRIMARY KEY, b);
    INSERT INTO t3 VALUES(1, 2);
    INSERT INTO t3 VALUES(3, 1);
  }
} {}
do_test subquery-2.2.2 {
  execsql {
    SELECT * FROM t3 WHERE a IN (SELECT b FROM t3);
  }
} {1 2}
do_test subquery-2.2.3 {
  execsql {
    DROP TABLE t3;
  }
} {}
do_test subquery-2.3.1 {
  execsql {
    CREATE TABLE t3(a TEXT PRIMARY KEY);
    INSERT INTO t3 VALUES('10');
  }
} {}
do_test subquery-2.3.2 {
  execsql {
    SELECT a IN (10.0, 20) FROM t3;
  }
} {0}
do_test subquery-2.3.3 {
  execsql {
    DROP TABLE t3;
  }
} {}
do_test subquery-2.4.1 {
  execsql {
    CREATE TABLE t3(a TEXT PRIMARY KEY);
    INSERT INTO t3 VALUES('XX');
  }
} {}
do_test subquery-2.4.2 {
  execsql {
    SELECT count(*) FROM t3 WHERE a IN (SELECT 'XX')
  }
} {1}
do_test subquery-2.4.3 {
  execsql {
    DROP TABLE t3;
  }
} {}
do_test subquery-2.5.1 {
  execsql {
    CREATE TABLE t3(a INTEGER PRIMARY KEY);
    INSERT INTO t3 VALUES(10);

    CREATE TABLE t4(x TEXT PRIMARY KEY);
    INSERT INTO t4 VALUES('10.0');
  }
} {}
do_test subquery-2.5.2 {
  # In the expr "x IN (SELECT a FROM t3)" the RHS of the IN operator
  # has text affinity and the LHS has integer affinity.  The rule is
  # that we try to convert both sides to an integer before doing the
  # comparision.  Hence, the integer value 10 in t3 will compare equal
  # to the string value '10.0' in t4 because the t4 value will be
  # converted into an integer.
  execsql {
    SELECT * FROM t4 WHERE x IN (SELECT a FROM t3);
  }
} {10.0}
do_test subquery-2.5.3.1 {
  # The t4i index cannot be used to resolve the "x IN (...)" constraint
  # because the constraint has integer affinity but t4i has text affinity.
  execsql {
    CREATE INDEX t4i ON t4(x);
    SELECT * FROM t4 WHERE x IN (SELECT a FROM t3);
  }
} {10.0}
# Tarantool: no-rowid is implied for the table, so query plan contains
# scan over t4i. Verified w/ vanilla SQLite. Comment this case
#do_test subquery-2.5.3.2 {
  # Verify that the t4i index was not used in the previous query
#  execsql {
#    EXPLAIN QUERY PLAN
#    SELECT * FROM t4 WHERE x IN (SELECT a FROM t3);
#  }
#} {~/t4i/}
do_test subquery-2.5.4 {
  execsql {
    DROP TABLE t3;
    DROP TABLE t4;
  }
} {}

#------------------------------------------------------------------
# The following test cases - subquery-3.* - test tickets that
# were raised during development of correlated subqueries.
#

# Ticket 1083
ifcapable view {
  do_test subquery-3.1 {
    catchsql { DROP TABLE t1; }
    catchsql { DROP TABLE t2; }
    execsql {
      CREATE TABLE t1(a PRIMARY KEY,b);
      INSERT INTO t1 VALUES(1,2);
      CREATE VIEW v1 AS SELECT b FROM t1 WHERE a>0;
      CREATE TABLE t2(p PRIMARY KEY,q);
      INSERT INTO t2 VALUES(2,9);
      SELECT * FROM v1 WHERE EXISTS(SELECT * FROM t2 WHERE p=v1.b);
    }
  } {2}
  do_test subquery-3.1.1 {
    execsql {
      SELECT * FROM v1 WHERE EXISTS(SELECT 1);
    }
  } {2}
} else {
  catchsql { DROP TABLE t1; }
  catchsql { DROP TABLE t2; }
  execsql {
    CREATE TABLE t1(a PRIMARY KEY,b);
    INSERT INTO t1 VALUES(1,2);
    CREATE TABLE t2(p PRIMARY KEY,q);
    INSERT INTO t2 VALUES(2,9);
  }
}

# Ticket 1084
do_test subquery-3.2 {
  catchsql {
    CREATE TABLE t1(a PRIMARY KEY,b);
    INSERT INTO t1 VALUES(1,2);
  }
  execsql {
    SELECT (SELECT t1.a) FROM t1;
  }
} {1}

# Test Cases subquery-3.3.* test correlated subqueries where the
# parent query is an aggregate query. Ticket #1105 is an example
# of such a query.
#
do_test subquery-3.3.1 {
  execsql {
    SELECT a, (SELECT b) FROM t1 GROUP BY a;
  }
} {1 2}
do_test subquery-3.3.2 {
  catchsql {DROP TABLE t2}
  execsql {
    CREATE TABLE t2(c PRIMARY KEY, d);
    INSERT INTO t2 VALUES(1, 'one');
    INSERT INTO t2 VALUES(2, 'two');
    SELECT a, (SELECT d FROM t2 WHERE a=c) FROM t1 GROUP BY a;
  }
} {1 one}
do_test subquery-3.3.3 {
  execsql {
    INSERT INTO t1 VALUES(2, 4);
    SELECT max(a), (SELECT d FROM t2 WHERE a=c) FROM t1;
  }
} {2 two}
do_test subquery-3.3.4 {
  execsql {
    SELECT a, (SELECT (SELECT d FROM t2 WHERE a=c)) FROM t1 GROUP BY a;
  }
} {1 one 2 two}
do_test subquery-3.3.5 {
  execsql {
    SELECT a, (SELECT count(*) FROM t2 WHERE a=c) FROM t1;
  }
} {1 1 2 1}

# The following tests check for aggregate subqueries in an aggregate
# query.
#
do_test subquery-3.4.1 {
  execsql {
    CREATE TABLE t34(id primary key, x,y);
    INSERT INTO t34 VALUES(1, 106,4), (2, 107,3), (3, 106,5), (4, 107,5);
    SELECT a.x, avg(a.y)
      FROM t34 AS a
     GROUP BY a.x
     HAVING NOT EXISTS( SELECT b.x, avg(b.y)
                          FROM t34 AS b
                         GROUP BY b.x
                         HAVING avg(a.y) > avg(b.y));
  }
} {107 4.0}
do_test subquery-3.4.2 {
  execsql {
    SELECT a.x, avg(a.y) AS avg1
      FROM t34 AS a
     GROUP BY a.x
     HAVING NOT EXISTS( SELECT b.x, avg(b.y) AS avg2
                          FROM t34 AS b
                         GROUP BY b.x
                         HAVING avg1 > avg2);
  }
} {107 4.0}
do_test subquery-3.4.3 {
  execsql {
    SELECT
       a.x,
       avg(a.y),
       NOT EXISTS ( SELECT b.x, avg(b.y)
                      FROM t34 AS b
                      GROUP BY b.x
                     HAVING avg(a.y) > avg(b.y)),
       EXISTS ( SELECT c.x, avg(c.y)
                  FROM t34 AS c
                  GROUP BY c.x
                 HAVING avg(a.y) > avg(c.y))
      FROM t34 AS a
     GROUP BY a.x
     ORDER BY a.x;
  }
} {106 4.5 0 1 107 4.0 1 0}

do_test subquery-3.5.1 {
  execsql {
    CREATE TABLE t35a(x PRIMARY KEY); INSERT INTO t35a VALUES(1),(2),(3);
    CREATE TABLE t35b(y PRIMARY KEY); INSERT INTO t35b VALUES(98), (99);
    SELECT max((SELECT avg(y) FROM t35b)) FROM t35a;
  }
} {98.5}
do_test subquery-3.5.2 {
  execsql {
    SELECT max((SELECT count(y) FROM t35b)) FROM t35a;
  }
} {2}
do_test subquery-3.5.3 {
  execsql {
    SELECT max((SELECT count() FROM t35b)) FROM t35a;
  }
} {2}
do_test subquery-3.5.4 {
  catchsql {
    SELECT max((SELECT count(x) FROM t35b)) FROM t35a;
  }
} {1 {misuse of aggregate: count()}}
do_test subquery-3.5.5 {
  catchsql {
    SELECT max((SELECT count(x) FROM t35b)) FROM t35a;
  }
} {1 {misuse of aggregate: count()}}
do_test subquery-3.5.6 {
  catchsql {
    SELECT max((SELECT a FROM (SELECT count(x) AS a FROM t35b))) FROM t35a;
  }
} {1 {misuse of aggregate: count()}}
do_test subquery-3.5.7 {
  execsql {
    SELECT max((SELECT a FROM (SELECT count(y) AS a FROM t35b))) FROM t35a;
  }
} {2}


#------------------------------------------------------------------
# These tests - subquery-4.* - use the TCL statement cache to try 
# and expose bugs to do with re-using statements that have been 
# passed to sqlite3_reset().
#
# One problem was that VDBE memory cells were not being initialized
# to NULL on the second and subsequent executions.
#
do_test subquery-4.1.1 {
  execsql {
    SELECT (SELECT a FROM t1);
  }
} {1}
do_test subquery-4.2 {
  execsql {
    DELETE FROM t1;
    SELECT (SELECT a FROM t1);
  }
} {{}}
do_test subquery-4.2.1 {
  execsql {
    CREATE TABLE t3(a PRIMARY KEY);
    INSERT INTO t3 VALUES(10);
  }
  execsql {INSERT INTO t3 VALUES((SELECT max(a) FROM t3)+1)}
} {}
do_test subquery-4.2.2 {
  execsql {INSERT INTO t3 VALUES((SELECT max(a) FROM t3)+1)}
} {}

#------------------------------------------------------------------
# The subquery-5.* tests make sure string literals in double-quotes
# are handled efficiently.  Double-quote literals are first checked
# to see if they match any column names.  If there is not column name
# match then those literals are used a string constants.  When a
# double-quoted string appears, we want to make sure that the search
# for a matching column name did not cause an otherwise static subquery
# to become a dynamic (correlated) subquery.
#
do_test subquery-5.1 {
  proc callcntproc {n} {
    incr ::callcnt
    return $n
  }
  set callcnt 0
  db function callcnt callcntproc
  execsql {
    CREATE TABLE t4(x,y PRIMARY KEY);
    INSERT INTO t4 VALUES('one',1);
    INSERT INTO t4 VALUES('two',2);
    INSERT INTO t4 VALUES('three',3);
    INSERT INTO t4 VALUES('four',4);
    CREATE TABLE t5(a PRIMARY KEY,b);
    INSERT INTO t5 VALUES(1,11);
    INSERT INTO t5 VALUES(2,22);
    INSERT INTO t5 VALUES(3,33);
    INSERT INTO t5 VALUES(4,44);
    SELECT b FROM t5 WHERE a IN 
       (SELECT callcnt(y)+0 FROM t4 WHERE x="two")
  }
} {22}
do_test subquery-5.2 {
  # This is the key test.  The subquery should have only run once.  If
  # The double-quoted identifier "two" were causing the subquery to be
  # processed as a correlated subquery, then it would have run 4 times.
  set callcnt
} {1}


# Ticket #1380.  Make sure correlated subqueries on an IN clause work
# correctly when the left-hand side of the IN operator is constant.
#
do_test subquery-6.1 {
  set callcnt 0
  execsql {
    SELECT x FROM t4 WHERE 1 IN (SELECT callcnt(count(*)) FROM t5 WHERE a=y)
  }
} {one two three four}
do_test subquery-6.2 {
  set callcnt
} {4}
do_test subquery-6.3 {
  set callcnt 0
  execsql {
    SELECT x FROM t4 WHERE 1 IN (SELECT callcnt(count(*)) FROM t5 WHERE a=1)
  }
} {one two three four}
do_test subquery-6.4 {
  set callcnt
} {1}

if 0 {   #############  disable until we get #2652 fixed
# Ticket #2652.  Allow aggregate functions of outer queries inside
# a non-aggregate subquery.
#
do_test subquery-7.1 {
  execsql {
    CREATE TABLE t7(c7 PRIMARY KEY);
    INSERT INTO t7 VALUES(1);
    INSERT INTO t7 VALUES(2);
    INSERT INTO t7 VALUES(3);
    CREATE TABLE t8(c8 PRIMARY KEY);
    INSERT INTO t8 VALUES(100);
    INSERT INTO t8 VALUES(200);
    INSERT INTO t8 VALUES(300);
    CREATE TABLE t9(c9 PRIMARY KEY);
    INSERT INTO t9 VALUES(10000);
    INSERT INTO t9 VALUES(20000);
    INSERT INTO t9 VALUES(30000);

    SELECT (SELECT c7+c8 FROM t7) FROM t8;
  }
} {101 201 301}
do_test subquery-7.2 {
  execsql {
    SELECT (SELECT max(c7)+c8 FROM t7) FROM t8;
  }
} {103 203 303}
do_test subquery-7.3 {
  execsql {
    SELECT (SELECT c7+max(c8) FROM t8) FROM t7
  }
} {301}
do_test subquery-7.4 {
  execsql {
    SELECT (SELECT max(c7)+max(c8) FROM t8) FROM t7
  }
} {303}
do_test subquery-7.5 {
  execsql {
    SELECT (SELECT c8 FROM t8 WHERE rowid=max(c7)) FROM t7
  }
} {300}
do_test subquery-7.6 {
  execsql {
    SELECT (SELECT (SELECT max(c7+c8+c9) FROM t9) FROM t8) FROM t7
  }
} {30101 30102 30103}
do_test subquery-7.7 {
  execsql {
    SELECT (SELECT (SELECT c7+max(c8+c9) FROM t9) FROM t8) FROM t7
  }
} {30101 30102 30103}
do_test subquery-7.8 {
  execsql {
    SELECT (SELECT (SELECT max(c7)+c8+c9 FROM t9) FROM t8) FROM t7
  }
} {10103}
do_test subquery-7.9 {
  execsql {
    SELECT (SELECT (SELECT c7+max(c8)+c9 FROM t9) FROM t8) FROM t7
  }
} {10301 10302 10303}
do_test subquery-7.10 {
  execsql {
    SELECT (SELECT (SELECT c7+c8+max(c9) FROM t9) FROM t8) FROM t7
  }
} {30101 30102 30103}
do_test subquery-7.11 {
  execsql {
    SELECT (SELECT (SELECT max(c7)+max(c8)+max(c9) FROM t9) FROM t8) FROM t7
  }
} {30303}
}  ;############# Disabled

# 2015-04-21.
# Verify that a memory leak in the table column type and collation analysis
# is plugged.
#
do_execsql_test subquery-8.1 {
  CREATE TABLE t8(a TEXT PRIMARY KEY, b INT);
  SELECT (SELECT 0 FROM (SELECT * FROM t1)) AS x WHERE x;
  SELECT (SELECT 0 FROM (SELECT * FROM (SELECT 0))) AS x WHERE x;
} {}

finish_test
