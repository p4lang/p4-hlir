/***************************************************************************/

extern_type counter {
        
    attribute type {
        /* Must be either:
            bytes
            packets
        */
        type: string;
    }

    attribute direct {
        /* Mutually exclusive with 'static' attribute */
        type: table;
        optional;
    }

    attribute static {
        /* Mutually exclusive with 'direct' attribute */
        type: table;
        optional;
    }

    attribute instance_count {
        type: int;
        optional;
    }

    attribute min_width {
        /* The minimum number of bits required for each cell. 
           The compiler or target may allocate more bits to each cell. */
        type: int;
        optional;
    }

    attribute saturating {
        /* Indicates that the counter will stop counting if it reaches
           its maximum value (based on its actual bit-width). Otherwise
           the counter will wrap. */
        type: void;
        optional;
    }

    /*
    Increment a cell in the counter array, either by 1 (if it is a
    packet counter) or by the packet length (if it is a byte
    counter). The index may be a table entry parameter or determined
    at compile time. It is an error to reference a direct-mapped
    counter array from this action.
    
    It is an error to call this method if the counter array is
    direct-mapped.

    Callable from:
    - Actions

    Parameters:
    - index: The offset in the counter array to update. May come
      from table entry data or be a compile time constant.
     */
    method count (in int index);
}

/***************************************************************************/

extern_type meter {
        
    attribute type {
        /* Must be either:
            bytes
            packets
        */
        type: string;
    }

    attribute direct {
        /* Mutually exclusive with 'static' attribute */
        /* Must be a table reference */
        type: table;
        optional;
    }

    attribute static {
        /* Mutually exclusive with 'direct' attribute */
        /* Must be a table reference */
        type: table;
        optional;
    }

    attribute instance_count {
        type: int;
        optional;
    }

    /*  
    Execute the metering operation for a given cell in the array. If
    the  meter is direct, then 'index' is ignored as the table
    entry determines which cell to reference. The length of the packet
    is implicitly passed to the meter. The state of meter is updated
    and the meter returns information (a 'color') which is stored in 
    'destination'. If the parent header of 'destination' is not valid,
    the meter  state is updated, but resulting output is discarded.

    Callable from:
    - Actions

    Parameters:
    - destination: A field reference to store the meter state.
    - index: Optional. The offset in the meter array to update. Necessary
      unless the meter is declared as direct, in which case it should not
      be present.
    */
    method execute (out bit<0> destination, optional in int index);
}

/***************************************************************************/

extern_type hash_calculation {
    attribute input {
        type: field_list ;
    }
    attribute algorithm {
        /* Specifies the hash algorithm to perform.
           May be (among others):
                xor16
                crc16
                crc32
                csum16
                optional_csum16
                programmable_crc
        */
        type: string;
    }
    attribute output_width {
        type: int;
    }

    /*
    Perform the calculation and write it into the destination.

    If the base argument is present, the value returned is the result
    summed with the base:

        destination = base + calc_result

    If the size argument is present, the value returned is fit into
    the range [base, base+size):

        destination = base + (calc_result \% size)

    Normal value conversion takes place when setting the final resulting
    value into the destination.

    Callable from:
    - Actions

    Parameters:
    - destination: A field reference indicating where to save the result
    - range_base: Optional. An integer, the base value to add to the
        calculation result.
    - range_size: Optional. An integer, the size of the range of values
        possible to return.
    */
    method get_value (
        out bit<0>   destination,
        optional in int range_base,
        optional in int range_size
    );

}

/***************************************************************************/

extern_type streaming_checksum {
    attribute algorithm {
        /*
        Streaming checksum algorithm to use. Currently either:
            csum16
            optional_csum16
        Targets may define additional algorithms.
        */
        type: string;
    }

    /*
    Include data in the checksum calculation.
    
    Callable from:
    - Parse states

    Parameters:
    - data: A reference to either a header instance, specific field, or
        integer literal
    */
    method append_data     (in bit<0> data);

    // TODO: Add once there is support for generic header params: 
    //method append_header   (in header data);
    //method append_metadata (in metadata data);

    /*
    Determine whether or not the current value of the checksum calculation 
    is correct (eg, for the csum16 family of algorthms, equals zero) and 
    report the result.

    Callable from:
    - Parse states

    Parameters:
    - destination: A field reference. Write the boolean result of the 
        verification operation into this field.
    - assert: Halt parsing immediately if the checksum is not valid
    */
    method verify_value (out bit<0> destination, in bit assert);

    /*
    Write the current value of the checksum calculation to a field.

    Callable from:
    - Parse states

    Parameters:
    - destination: A field reference. Write the checksum value into this
        field.
    */
    method get_value (out bit<0> destination);

}

/***************************************************************************/

extern_type checksum_updater {
    attribute source_calculation {
        type: extern hash_calculation;
    }

    attribute destination {
        /* Must be a field */
        type: bit<0>;
    }

    attribute predicate {
        /* Default is 'true' */
        type: expression;
        optional;
    }

    attribute order {
        /* Default is 0 */
        type: int;
        optional;
    }
}

/***************************************************************************/

extern_type action_profile {
    attribute size {
        type: int;
        optional;
    }
    attribute dynamic_action_selection {
        type: extern hash_calculation;
        optional;
    }
}

/***************************************************************************/

extern_type digest_receiver {
    method send_digest (in field_list digest);
}