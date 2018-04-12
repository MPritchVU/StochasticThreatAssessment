(define (problem ER-Full)
	(:domain attack_planning)
	(:init
		(has_file host0 File)
		(connected host0 host0))
	(:goal
		(accessed File)))
