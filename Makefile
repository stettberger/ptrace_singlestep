all: singlestepper null
	./singlestepper null

singlestepper: singlestepper.cc
	g++ singlestepper.cc -o $@ -O3 -lboost_regex

null: null.cc
	g++ null.cc -o null -static
